// syscall_trace.c — Scrutiny v2 syscall sensor
//
// Hooks raw_syscalls:sys_enter via a RAW tracepoint (BPF_RAW_TRACEPOINT_OPEN),
// NOT a perf-based tracepoint. Some kernels — notably the Microsoft WSL2
// kernel — advertise BPF perf-event links but then reject BPF_LINK_CREATE on
// them with EPERM even for root, which makes the perf-based `tracepoint/...`
// attach unusable there. Raw tracepoints go straight through the bpf()
// syscall and attach cleanly across native Linux, WSL2, and minimal/embedded
// kernels.
//
// Deliberately avoids CO-RE/BTF struct relocation — the raw_syscalls
// tracepoint argument layout is part of the stable kernel tracing ABI, so
// reading ctx->args[] works without vmlinux.h. This keeps the probe portable
// to minimal kernels (Pi nodes) that may not ship BTF info.
//
// Filters to a single target PID set via the pid_filter map so we don't pay
// the ring-buffer cost for every process on the box — critical for keeping
// overhead near the <5% eBPF target instead of strace's 50-100x.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

// ─── Event structure sent to userspace via ring buffer ──────────────────────

#define TASK_COMM_LEN 16
#define MAX_ARGS      6

struct syscall_event {
	__u64 timestamp_ns;
	__u32 pid;
	__u32 tid;
	__s64 syscall_nr;
	__u64 args[MAX_ARGS];
	__s64 ret;        // reserved; populated once the exit path is restored
	__u8  is_exit;     // 0 = enter (only path emitted today), 1 = exit
	char  comm[TASK_COMM_LEN];
};

// ─── Maps ─────────────────────────────────────────────────────────────────────

// Ring buffer for event delivery — requires kernel >= 5.8. The Go loader
// gates on that before ever loading this object (see sensor.Probe).
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24); // 16MB
} events SEC(".maps");

// PID filter — only PIDs present in this map (value = 1) are traced.
// Populated by the Go loader before attach, one entry per baseline/observe run.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16);
	__type(key, __u32);
	__type(value, __u8);
} pid_filter SEC(".maps");

// ns_info carries the target's PID-namespace identity (dev+inode of
// /proc/<pid>/ns/pid), written once by the Go loader. The probe uses it with
// bpf_get_ns_current_pid_tgid() so the PID it filters on is numbered in the
// SAME namespace userspace sees — essential when the target runs inside a
// nested PID namespace (systemd-on-WSL2, containers), where the kernel's
// global PID differs from the namespace-local PID passed to --pid.
struct ns_dev_ino {
	__u64 dev;
	__u64 ino;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct ns_dev_ino);
} ns_info SEC(".maps");

// ─── Helpers ─────────────────────────────────────────────────────────────────

static __always_inline int pid_is_tracked(__u32 pid) {
	__u8 *found = bpf_map_lookup_elem(&pid_filter, &pid);
	return found != NULL;
}

// ─── Probe ───────────────────────────────────────────────────────────────────
//
// raw_syscalls:sys_enter is declared TP_PROTO(struct pt_regs *regs, long id),
// so the raw-tracepoint context carries:
//   ctx->args[0] = struct pt_regs *regs
//   ctx->args[1] = long syscall_nr
//
// We record the syscall number, which is all the current baseline/analysis
// path consumes. Per-syscall argument values live in pt_regs and are
// arch-specific to decode (regs->orig_ax, regs->di, ...); that decode — and
// the matching sys_exit return-value/latency path — is intentionally deferred
// (args[] left zero) until CO-RE/vmlinux.h is wired in. Attaching only
// sys_enter also means each syscall invocation is counted exactly once.
SEC("raw_tracepoint/sys_enter")
int trace_sys_enter(struct bpf_raw_tracepoint_args *ctx) {
	// Resolve this task's PID/TGID within the target's PID namespace, so the
	// number matches what userspace passed to --pid. Falls back to nothing
	// (drop the event) if ns_info is unset or the current task is not a member
	// of that namespace — which is exactly the set of processes we don't care
	// about when watching a namespaced target.
	__u32 zero = 0;
	struct ns_dev_ino *ns = bpf_map_lookup_elem(&ns_info, &zero);
	if (!ns)
		return 0;

	struct bpf_pidns_info nsinfo = {};
	if (bpf_get_ns_current_pid_tgid(ns->dev, ns->ino, &nsinfo, sizeof(nsinfo)) != 0)
		return 0; // current task is outside the target namespace

	__u32 pid = nsinfo.tgid;
	__u32 tid = nsinfo.pid;

	if (!pid_is_tracked(pid))
		return 0;

	struct syscall_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
	if (!evt)
		return 0; // ring buffer full — drop rather than block

	evt->timestamp_ns = bpf_ktime_get_ns();
	evt->pid = pid;
	evt->tid = tid;
	evt->syscall_nr = (__s64)ctx->args[1];
	evt->ret = 0;
	evt->is_exit = 0;
	bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

	#pragma unroll
	for (int i = 0; i < MAX_ARGS; i++) {
		evt->args[i] = 0; // arg decode deferred — see comment above
	}

	bpf_ringbuf_submit(evt, 0);
	return 0;
}
