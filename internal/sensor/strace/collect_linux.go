//go:build linux

package strace

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"time"

	"github.com/MoSLoF/scrutiny2.0/internal/schema"
)

// Collect drives strace against the target for the given duration and returns
// a syscall observation. The filesystem observation is empty for now — strace
// decodes file paths too, but extracting them from arbitrary decoded lines is
// a follow-up; this first cut delivers the syscall dimension the fallback
// exists for. platformCtx is accepted for signature parity with ebpf.Collect
// (used once filesystem decoding lands).
//
// Scope note: `-f` follows threads AND children, so the strace fallback records
// the target's process subtree, not just its TGID like the eBPF backend. That
// is symmetric across baseline and observation, so comparisons stay valid.
func Collect(pid uint32, duration time.Duration, platformCtx schema.PlatformContext) (*schema.SyscallsObservation, *schema.FilesystemObservation, error) {
	_ = platformCtx

	cmd := exec.Command("strace",
		"-f",        // follow threads and children
		"-ttt",      // absolute epoch timestamps, for offsets
		"-T",        // syscall duration, for latency
		"-qq",       // suppress attach/detach/exit chatter
		"-s", "128", // cap decoded string length
		"-p", strconv.Itoa(int(pid)),
	)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("strace stderr pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, fmt.Errorf("starting strace (installed? has CAP_SYS_PTRACE?): %w", err)
	}

	obs := &schema.SyscallsObservation{Observed: map[string]schema.SyscallRecord{}}
	var firstTs int64

	done := make(chan struct{})
	go func() {
		defer close(done)
		sc := bufio.NewScanner(stderr)
		sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
		for sc.Scan() {
			if e, ok := parseLine(sc.Text()); ok {
				record(obs, e, &firstTs)
			}
		}
	}()

	time.Sleep(duration)

	// SIGINT makes strace detach cleanly and exit, which EOFs the pipe and
	// ends the scanner. Fall back to a kill if it doesn't stop promptly.
	_ = cmd.Process.Signal(os.Interrupt)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		_ = cmd.Process.Kill()
		<-done
	}
	_ = cmd.Wait()

	obs.SuspiciousNeverExpected = suspiciousNeverExpected
	return obs, &schema.FilesystemObservation{}, nil
}
