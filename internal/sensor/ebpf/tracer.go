//go:build linux

// Package ebpf wraps the compiled eBPF programs in internal/sensor/ebpf/bpf/
// and exposes a Go-native collection interface. Kept separate from the
// strace fallback (internal/sensor/strace/) — both implement the same
// sensor.SyscallCollector interface so the CLI layer doesn't care which
// backend is active.
package ebpf

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"fmt"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/MoSLoF/scrutiny/internal/schema"
)

//go:embed bpf/syscall_trace.o
var syscallTraceObj []byte

// syscallEvent mirrors the C struct syscall_event byte-for-byte.
// Field order and sizes MUST match bpf/syscall_trace.c exactly —
// this is read via binary.Read against the raw ring buffer bytes.
type syscallEvent struct {
	TimestampNS uint64
	LatencyNS   uint64
	PID         uint32
	TID         uint32
	SyscallNr   int64
	Args        [6]uint64
	Ret         int64
	IsExit      uint8
	_           [7]byte // matches struct syscall_event's explicit _pad[7]
	Comm        [16]byte
}

// SyscallTracer manages the lifecycle of the syscall eBPF probe:
// load -> attach -> filter PIDs -> consume ring buffer -> detach.
type SyscallTracer struct {
	coll      *ebpf.Collection
	enterLink link.Link
	exitLink  link.Link
	reader    *ringbuf.Reader
	pidFilter *ebpf.Map
	startTime time.Time
	events    chan syscallEvent
	stopCh    chan struct{}
}

// NewSyscallTracer loads the embedded eBPF object and attaches both
// tracepoints. Returns an error if the kernel rejects the load —
// callers should catch this and fall back to strace (see sensor.Probe).
func NewSyscallTracer() (*SyscallTracer, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("removing memlock rlimit: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(syscallTraceObj))
	if err != nil {
		return nil, fmt.Errorf("parsing eBPF object: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("loading eBPF collection into kernel: %w", err)
	}

	enterProg, ok := coll.Programs["trace_sys_enter"]
	if !ok {
		coll.Close()
		return nil, fmt.Errorf("trace_sys_enter program not found in object")
	}
	exitProg, ok := coll.Programs["trace_sys_exit"]
	if !ok {
		coll.Close()
		return nil, fmt.Errorf("trace_sys_exit program not found in object")
	}
	pidFilter, ok := coll.Maps["pid_filter"]
	if !ok {
		coll.Close()
		return nil, fmt.Errorf("pid_filter map not found in object")
	}
	eventsMap, ok := coll.Maps["events"]
	if !ok {
		coll.Close()
		return nil, fmt.Errorf("events ring buffer map not found in object")
	}

	// Raw tracepoint (BPF_RAW_TRACEPOINT_OPEN) rather than a perf-based
	// tracepoint: the perf-link path is rejected with EPERM on some kernels
	// (e.g. Microsoft's WSL2 kernel) even for root. Raw tracepoints attach
	// through the bpf() syscall directly and work across native Linux, WSL2,
	// and minimal kernels. See bpf/syscall_trace.c for the matching probe.
	enterLink, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_enter",
		Program: enterProg,
	})
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("attaching sys_enter raw tracepoint: %w", err)
	}

	exitLink, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_exit",
		Program: exitProg,
	})
	if err != nil {
		enterLink.Close()
		coll.Close()
		return nil, fmt.Errorf("attaching sys_exit raw tracepoint: %w", err)
	}

	reader, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		exitLink.Close()
		enterLink.Close()
		coll.Close()
		return nil, fmt.Errorf("opening ring buffer reader: %w", err)
	}

	return &SyscallTracer{
		coll:      coll,
		enterLink: enterLink,
		exitLink:  exitLink,
		reader:    reader,
		pidFilter: pidFilter,
		events:    make(chan syscallEvent, 4096),
		stopCh:    make(chan struct{}),
	}, nil
}

// nsDevIno mirrors `struct ns_dev_ino` in bpf/syscall_trace.c (two u64s).
type nsDevIno struct {
	Dev uint64
	Ino uint64
}

// SetTargetNS records the target PID's namespace identity (dev+inode of
// /proc/<pid>/ns/pid) into the ns_info map, so the probe resolves PIDs in the
// same namespace userspace numbered --pid in. Without this, a nested PID
// namespace (systemd-on-WSL2, containers) makes the kernel's global PID
// disagree with the namespace-local PID and the filter never matches.
func (t *SyscallTracer) SetTargetNS(pid uint32) error {
	m, ok := t.coll.Maps["ns_info"]
	if !ok {
		return fmt.Errorf("ns_info map not found in object")
	}
	var st syscall.Stat_t
	path := fmt.Sprintf("/proc/%d/ns/pid", pid)
	if err := syscall.Stat(path, &st); err != nil {
		// Fall back to our own namespace — the common case is that scrutiny
		// and the target share it.
		if err2 := syscall.Stat("/proc/self/ns/pid", &st); err2 != nil {
			return fmt.Errorf("stat %s (and self): %w", path, err)
		}
	}
	var key uint32
	return m.Put(key, nsDevIno{Dev: uint64(st.Dev), Ino: uint64(st.Ino)})
}

// TrackPID adds a PID to the kernel-side filter map. Only tracked PIDs
// generate ring buffer events — untracked syscalls are dropped in-kernel,
// which is the whole point of eBPF over strace's userspace-copy-everything
// approach.
func (t *SyscallTracer) TrackPID(pid uint32) error {
	var one uint8 = 1
	return t.pidFilter.Put(pid, one)
}

// UntrackPID removes a PID from the filter, stopping event generation for it.
func (t *SyscallTracer) UntrackPID(pid uint32) error {
	return t.pidFilter.Delete(pid)
}

// Start begins consuming ring buffer events in a background goroutine.
// Events are delivered on t.Events(). Call Stop() to end collection.
func (t *SyscallTracer) Start() {
	t.startTime = time.Now()
	go t.readLoop()
}

func (t *SyscallTracer) readLoop() {
	for {
		select {
		case <-t.stopCh:
			return
		default:
		}

		record, err := t.reader.Read()
		if err != nil {
			if err == ringbuf.ErrClosed {
				return
			}
			continue // transient read error — keep going
		}

		var evt syscallEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &evt); err != nil {
			continue
		}

		select {
		case t.events <- evt:
		default:
			// consumer too slow — drop rather than block the kernel-side ring
		}
	}
}

// Events returns the channel of decoded syscall events.
func (t *SyscallTracer) Events() <-chan syscallEvent {
	return t.events
}

// Stop halts collection and releases all kernel resources.
func (t *SyscallTracer) Stop() {
	close(t.stopCh)
	t.reader.Close()
	t.exitLink.Close()
	t.enterLink.Close()
	t.coll.Close()
}

// Collect runs the tracer against a PID for the given duration and
// returns a populated schema.SyscallsObservation. This is the primary
// entry point called from the baseline/observe CLI commands.
func Collect(pid uint32, duration time.Duration) (*schema.SyscallsObservation, error) {
	tracer, err := NewSyscallTracer()
	if err != nil {
		return nil, err
	}
	defer tracer.Stop()

	if err := tracer.SetTargetNS(pid); err != nil {
		return nil, fmt.Errorf("resolving target namespace for pid %d: %w", pid, err)
	}

	if err := tracer.TrackPID(pid); err != nil {
		return nil, fmt.Errorf("tracking pid %d: %w", pid, err)
	}

	tracer.Start()

	obs := &schema.SyscallsObservation{
		Observed: make(map[string]schema.SyscallRecord),
	}

	timeout := time.After(duration)

	// firstEventNS anchors all offsets to the first observed event's
	// kernel timestamp. evt.TimestampNS comes from bpf_ktime_get_ns
	// (monotonic since boot), so it must NOT be mixed with a wall-clock
	// reference — offsets are computed within the monotonic domain only.
	var firstEventNS int64

	for {
		select {
		case <-timeout:
			finalizeSuspiciousFlags(obs)
			return obs, nil

		case evt, ok := <-tracer.events:
			if !ok {
				finalizeSuspiciousFlags(obs)
				return obs, nil
			}
			recordSyscallEvent(obs, evt, &firstEventNS)
		}
	}
}

const maxSamples = 3

func recordSyscallEvent(obs *schema.SyscallsObservation, evt syscallEvent, firstEventNS *int64) {
	name := syscallName(evt.SyscallNr)
	if *firstEventNS == 0 {
		*firstEventNS = int64(evt.TimestampNS)
	}
	offsetMS := (int64(evt.TimestampNS) - *firstEventNS) / 1e6

	rec, exists := obs.Observed[name]
	if !exists {
		rec = schema.SyscallRecord{FirstSeenOffsetMS: offsetMS}
	}
	rec.LastSeenOffsetMS = offsetMS

	if evt.IsExit == 0 {
		// Enter event: one per invocation, carrying the argument registers.
		rec.Count++
		if len(rec.ArgsSample) < maxSamples {
			rec.ArgsSample = append(rec.ArgsSample, formatArgs(evt.Args))
		}
	} else {
		// Exit event: return value + enter→exit latency.
		rec.ExitCount++
		if evt.Ret < 0 {
			rec.ErrorCount++
		}
		if len(rec.RetSample) < maxSamples {
			rec.RetSample = append(rec.RetSample, evt.Ret)
		}
		lat := int64(evt.LatencyNS)
		rec.TotalLatencyNS += lat
		if lat > rec.MaxLatencyNS {
			rec.MaxLatencyNS = lat
		}
	}

	obs.Observed[name] = rec
}

// formatArgs renders the six raw syscall-argument registers as hex. They are
// register values — pointers, sizes, flags, fds — so hex is the useful form.
func formatArgs(args [6]uint64) string {
	return fmt.Sprintf("0x%x 0x%x 0x%x 0x%x 0x%x 0x%x",
		args[0], args[1], args[2], args[3], args[4], args[5])
}

// finalizeSuspiciousFlags cross-references observed syscalls against the
// always-suspicious list seeded in schema.NewBaseline.
func finalizeSuspiciousFlags(obs *schema.SyscallsObservation) {
	suspicious := []string{
		"ptrace", "process_vm_readv", "process_vm_writev",
		"init_module", "finit_module", "delete_module",
		"kexec_load", "kexec_file_load",
	}
	seen := map[string]bool{}
	for _, s := range suspicious {
		if _, ok := obs.Observed[s]; ok {
			seen[s] = true
		}
	}
	obs.SuspiciousNeverExpected = suspicious
	_ = seen // anomaly cross-reference happens in the analysis engine (Phase 3)
}
