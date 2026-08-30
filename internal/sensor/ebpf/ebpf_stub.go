//go:build !linux

// Package ebpf — non-Linux stub.
//
// eBPF is a Linux kernel technology; on Windows the equivalent sensing
// role is filled by ETW/Sysmon (see internal/sensor/etw, Phase 2c).
// This stub exists solely so cmd/scrutiny can import this package
// unconditionally and still cross-compile clean for windows/amd64 and
// other non-Linux targets — the CLI picks the real backend at runtime
// via sensor.Probe, which never selects eBPF outside Linux.
package ebpf

import (
	"fmt"
	"time"

	"github.com/MoSLoF/scrutiny2.0/internal/schema"
)

// SyscallTracer stub — see tracer.go for the real Linux implementation.
type SyscallTracer struct{}

// NewSyscallTracer always fails on non-Linux, mirroring the real
// implementation's error-return contract so capability.go's
// liveEBPFProbe() works unmodified across platforms.
func NewSyscallTracer() (*SyscallTracer, error) {
	return nil, fmt.Errorf("eBPF is Linux-only")
}

// Stop is a no-op stub to satisfy capability.go's cross-platform call site.
func (t *SyscallTracer) Stop() {}

// Collect always returns an error on non-Linux platforms. The CLI
// layer never calls this in practice — sensor.Probe's Backend selection
// steers Windows to the ETW/Sysmon collector instead — but the function
// must exist with a matching signature for the package to compile here.
func Collect(pid uint32, duration time.Duration) (*schema.SyscallsObservation, error) {
	return nil, fmt.Errorf("eBPF is Linux-only; use the ETW/Sysmon backend on this platform")
}
