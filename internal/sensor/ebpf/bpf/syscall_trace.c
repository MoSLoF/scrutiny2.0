// syscall_trace.c — Scrutiny v2 syscall sensor
//
// Hooks raw_syscalls:sys_enter and raw_syscalls:sys_exit via RAW tracepoints
// (BPF_RAW_TRACEPOINT_OPEN), NOT perf-based tracepoints. Some kernels —
// notably the Microsoft WSL2 kernel — advertise BPF perf-event links but then
// reject BPF_LINK_CREATE on them with EPERM even for root, which makes the
// perf-based `tracepoint/...` attach unusable there. Raw tracepoints go
// straight through the bpf() syscall and attach cleanly across native Linux,
// WSL2, and minimal/embedded kernels.
//
// Argument capture uses CO-RE: pt_regs is declared locally with
// __attribute__((preserve_access_index)) so clang emits field relocations that
// the loader resolves against the running kernel's BTF at load time. This gets
// us portable per-syscall argument reads WITHOUT shipping a multi-megabyte
// vmlinux.h (and without a bpftool build dependency). The register→argument
// mapping is the x86_64 syscall calling convention — matching the x86_64-only
// syscall name table (syscall_table.go).
//
// Filters to a single target PID set via the pid_filter map so we don't pay
// the ring-buffer cost for every process on the box — critical for keeping
// overhead near the <5% eBPF target instead of strace's 50-100x.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// ─── Minimal CO-RE pt_regs (x86_64) ──────────────────────────────────────────
// Only the fields we read are declared; preserve_access_index makes clang emit
// CO-RE relocations keyed by field NAME, so the local offsets here are
// irrelevant — the loader rewrites them to the target kernel's real offsets.
// Field names must match the kernel's struct pt_regs (di, si, dx, r10, r8, r9).
struct pt_regs {
	unsigned long di;
	unsigned long si;
	unsigned long dx;
	unsigned long r10;
	unsigned long r8;
	unsigned long r9;
} __attribute__((preserve_access_index));

// ─── Event structure sent to userspace via ring buffer ──────────────────────

#define TASK_COMM_LEN 16
#define MAX_ARGS      6

struct syscall_event {
	__u64 timestamp_ns;
	__u64 latency_ns;  // exit events only (enter→exit delta); 0 on enter
	__u32 pid;
	__u32 tid;
	__s64 syscall_nr;
	__u64 args[MAX_ARGS]; // populated on enter; zero on exit
	__s64 ret;            // exit events only; 0 on enter
	__u8  is_exit;         // 0 = enter, 1 = exit
	__u8  _pad[7];         // explicit pad so `comm` aligns with the Go struct
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

// active tracks the in-flight syscall per thread so sys_exit can recover the
// syscall number (the exit tracepoint only carries the return value) and
// compute latency. Keyed by the GLOBAL pid_tgid (unique per thread, always
// available); only tracked PIDs ever get an entry, so it stays small.
struct active_syscall {
	__s64 nr;
	__u64 enter_ts;
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, struct active_syscall);
} active SEC(".maps");

// ─── Helpers ─────────────────────────────────────────────────────────────────

static __always_inline int pid_is_tracked(__u32 pid) {
	__u8 *found = bpf_map_lookup_elem(&pid_filter, &pid);
	return found != NULL;
}

// resolve_ns_pid fills *pid/*tid with the current task's TGID/PID as numbered
// in the target's namespace, and reports whether the task belongs to it.
static __always_inline int resolve_ns_pid(__u32 *pid, __u32 *tid) {
	__u32 zero = 0;
	struct ns_dev_ino *ns = bpf_map_lookup_elem(&ns_info, &zero);
	if (!ns)
		return 0;
	struct bpf_pidns_info nsinfo = {};
	if (bpf_get_ns_current_pid_tgid(ns->dev, ns->ino, &nsinfo, sizeof(nsinfo)) != 0)
		return 0;
	*pid = nsinfo.tgid;
	*tid = nsinfo.pid;
	return 1;
}

// ─── Probes ──────────────────────────────────────────────────────────────────
//
// raw_syscalls:sys_enter is TP_PROTO(struct pt_regs *regs, long id):
//   ctx->args[0] = struct pt_regs *regs   ctx->args[1] = long syscall_nr
// raw_syscalls:sys_exit is TP_PROTO(struct pt_regs *regs, long ret):
//   ctx->args[0] = struct pt_regs *regs   ctx->args[1] = long ret

SEC("raw_tracepoint/sys_enter")
int trace_sys_enter(struct bpf_raw_tracepoint_args *ctx) {
	__u32 pid, tid;
	if (!resolve_ns_pid(&pid, &tid))
		return 0;
	if (!pid_is_tracked(pid))
		return 0;

	struct pt_regs *regs = (struct pt_regs *)ctx->args[0];
	__s64 nr = (__s64)ctx->args[1];
	__u64 ts = bpf_ktime_get_ns();

	// Record the in-flight syscall for the exit probe (nr + start time).
	__u64 gtid = bpf_get_current_pid_tgid();
	struct active_syscall a = {.nr = nr, .enter_ts = ts};
	bpf_map_update_elem(&active, &gtid, &a, BPF_ANY);

	struct syscall_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
	if (!evt)
		return 0; // ring buffer full — drop rather than block

	evt->timestamp_ns = ts;
	evt->latency_ns = 0;
	evt->pid = pid;
	evt->tid = tid;
	evt->syscall_nr = nr;
	evt->ret = 0;
	evt->is_exit = 0;
	bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

	// x86_64 syscall arguments, read from pt_regs via CO-RE.
	evt->args[0] = BPF_CORE_READ(regs, di);
	evt->args[1] = BPF_CORE_READ(regs, si);
	evt->args[2] = BPF_CORE_READ(regs, dx);
	evt->args[3] = BPF_CORE_READ(regs, r10);
	evt->args[4] = BPF_CORE_READ(regs, r8);
	evt->args[5] = BPF_CORE_READ(regs, r9);

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

SEC("raw_tracepoint/sys_exit")
int trace_sys_exit(struct bpf_raw_tracepoint_args *ctx) {
	__u32 pid, tid;
	if (!resolve_ns_pid(&pid, &tid))
		return 0;
	if (!pid_is_tracked(pid))
		return 0;

	__u64 gtid = bpf_get_current_pid_tgid();
	struct active_syscall *a = bpf_map_lookup_elem(&active, &gtid);
	if (!a)
		return 0; // enter happened before tracking began — nothing to pair

	__u64 now = bpf_ktime_get_ns();

	struct syscall_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
	if (!evt) {
		bpf_map_delete_elem(&active, &gtid);
		return 0;
	}

	evt->timestamp_ns = now;
	evt->latency_ns = now - a->enter_ts;
	evt->pid = pid;
	evt->tid = tid;
	evt->syscall_nr = a->nr;
	evt->ret = (__s64)ctx->args[1];
	evt->is_exit = 1;
	bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

	#pragma unroll
	for (int i = 0; i < MAX_ARGS; i++)
		evt->args[i] = 0; // args belong to the enter event

	bpf_ringbuf_submit(evt, 0);
	bpf_map_delete_elem(&active, &gtid);
	return 0;
}
