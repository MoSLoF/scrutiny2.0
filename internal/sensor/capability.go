// Package sensor provides the sensor capability detection and selection
// logic for Scrutiny v2. The active backend is determined at runtime
// based on kernel version, available capabilities, and execution context.
//
// Selection hierarchy:
//
//  1. eBPF with ring buffers (kernel >= 5.8, CAP_BPF/root) — optimal
//  2. eBPF with perf buffers (kernel >= 4.15, CAP_BPF/root) — good
//  3. strace (CAP_SYS_PTRACE or root)                       — fallback
//  4. Network + filesystem polling only (neither available)  — degraded
package sensor

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/MoSLoF/scrutiny/internal/schema"
	"github.com/MoSLoF/scrutiny/internal/sensor/ebpf"
)

// CapabilityReport is the full output of the capability probe.
// It's stored in the baseline's PlatformContext so the analysis engine
// knows exactly what the sensor could and could not see.
type CapabilityReport struct {
	Backend           schema.SensorBackend
	EBPFAvailable     bool
	EBPFRingBuffer    bool // kernel >= 5.8
	EBPFPerfBuffer    bool // kernel >= 4.15
	KernelMajor       int
	KernelMinor       int
	KernelPatch       int
	HasCAP_BPF        bool
	HasCAP_SYS_PTRACE bool
	StraceAvailable   bool
	StraceVersion     string
	ForcedFallback    bool // true if eBPF was skipped due to context (WSL1 etc.)
	FallbackReason    string
	Warnings          []string
}

// String returns a human-readable summary for startup output.
func (c CapabilityReport) String() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Sensor backend: %s\n", c.Backend))
	sb.WriteString(fmt.Sprintf("  Kernel:         %d.%d.%d\n", c.KernelMajor, c.KernelMinor, c.KernelPatch))
	sb.WriteString(fmt.Sprintf("  eBPF available: %v", c.EBPFAvailable))
	if c.EBPFAvailable {
		if c.EBPFRingBuffer {
			sb.WriteString(" (ring buffer mode)")
		} else {
			sb.WriteString(" (perf buffer mode)")
		}
	}
	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("  strace:         %v", c.StraceAvailable))
	if c.StraceAvailable && c.StraceVersion != "" {
		sb.WriteString(fmt.Sprintf(" (%s)", c.StraceVersion))
	}
	sb.WriteString("\n")
	if c.ForcedFallback {
		sb.WriteString(fmt.Sprintf("  eBPF skipped:   %s\n", c.FallbackReason))
	}
	for _, w := range c.Warnings {
		sb.WriteString(fmt.Sprintf("  WARNING:        %s\n", w))
	}
	return sb.String()
}

var kernelVersionRE = regexp.MustCompile(`(\d+)\.(\d+)\.(\d+)`)

// Probe runs the full capability detection and returns a CapabilityReport.
// Pass the execution context so that context-forced fallbacks are applied
// (e.g. WSL1 forces strace regardless of capability).
func Probe(ctx schema.PlatformContext) CapabilityReport {
	if runtime.GOOS == "windows" {
		return windowsReport()
	}
	return linuxProbe(ctx)
}

func linuxProbe(ctx schema.PlatformContext) CapabilityReport {
	r := CapabilityReport{}

	// ── Parse kernel version ──────────────────────────────────────────────
	r.KernelMajor, r.KernelMinor, r.KernelPatch = parseKernelVersion(ctx.KernelVersion)

	// ── strace check (always probe this as fallback) ──────────────────────
	r.StraceAvailable, r.StraceVersion = probeStrace()
	r.HasCAP_SYS_PTRACE = hasCap("cap_sys_ptrace") || os.Getuid() == 0

	// ── Context-forced fallback ───────────────────────────────────────────
	if ctx.DetectedPlatform == schema.ContextWSL1 {
		r.ForcedFallback = true
		r.FallbackReason = "WSL1 does not support eBPF — strace only"
		r.Backend = pickFallback(r)
		return r
	}

	// ── eBPF minimum kernel check ─────────────────────────────────────────
	if !kernelMeetsMin(r.KernelMajor, r.KernelMinor, 4, 15) {
		r.ForcedFallback = true
		r.FallbackReason = fmt.Sprintf(
			"kernel %d.%d.%d below eBPF minimum (4.15)",
			r.KernelMajor, r.KernelMinor, r.KernelPatch)
		r.Backend = pickFallback(r)
		return r
	}

	r.EBPFPerfBuffer = true
	if kernelMeetsMin(r.KernelMajor, r.KernelMinor, 5, 8) {
		r.EBPFRingBuffer = true
	}

	// ── Capability check ──────────────────────────────────────────────────
	r.HasCAP_BPF = hasCap("cap_bpf") || os.Getuid() == 0
	if !r.HasCAP_BPF {
		r.ForcedFallback = true
		r.FallbackReason = "CAP_BPF not available — run as root or grant cap_bpf"
		r.Warnings = append(r.Warnings,
			"eBPF requires CAP_BPF. Run: setcap cap_bpf+ep scrutiny")
		r.Backend = pickFallback(r)
		return r
	}

	// ── WSL2 partial eBPF support ─────────────────────────────────────────
	if ctx.DetectedPlatform == schema.ContextWSL2 {
		if !wsl2EBPFProbe() {
			r.ForcedFallback = true
			r.FallbackReason = "WSL2 kernel lacks CONFIG_BPF_SYSCALL — strace fallback"
			r.Warnings = append(r.Warnings,
				"Some WSL2 builds disable eBPF. Update Windows or enable in kernel config.")
			r.Backend = pickFallback(r)
			return r
		}
		r.Warnings = append(r.Warnings,
			"WSL2 eBPF: network visibility is forwarded through Windows host")
	}

	// ── Live eBPF probe — try loading a minimal program ───────────────────
	if err := liveEBPFProbe(r.HasCAP_BPF); err != nil {
		r.ForcedFallback = true
		r.FallbackReason = fmt.Sprintf("eBPF live probe failed: %v", err)
		r.Warnings = append(r.Warnings, r.FallbackReason)
		r.Backend = pickFallback(r)
		return r
	}

	r.EBPFAvailable = true
	r.Backend = schema.BackendEBPF
	return r
}

// ─── eBPF Probes ─────────────────────────────────────────────────────────────

// liveEBPFProbe attempts to load the actual syscall tracer to confirm the
// kernel will accept it. A capability check (CAP_BPF, kernel version) can
// pass while the load still fails due to kernel config, seccomp, LSM
// restrictions, or a locked-down distro kernel — so we do a real
// load-and-immediately-close rather than trusting the capability bits alone.
//
// The `privileged` flag reports whether we hold CAP_BPF (or are root).
// unprivileged_bpf_disabled={1,2} only restricts the bpf() syscall for
// *unprivileged* callers; a privileged load still succeeds. So we only
// treat that sysctl as a hard blocker when we are NOT privileged —
// otherwise we'd wrongly fall back to strace on every hardened kernel.
func liveEBPFProbe(privileged bool) error {
	if !privileged {
		bpfSyscallPath := "/proc/sys/kernel/unprivileged_bpf_disabled"
		if content, err := os.ReadFile(bpfSyscallPath); err == nil {
			val := strings.TrimSpace(string(content))
			if val == "1" || val == "2" {
				return fmt.Errorf("unprivileged_bpf_disabled=%s and no CAP_BPF (run as root or grant cap_bpf)", val)
			}
		}
	}

	tracer, err := ebpf.NewSyscallTracer()
	if err != nil {
		return err
	}
	tracer.Stop()
	return nil
}

// wsl2EBPFProbe checks if the WSL2 kernel was built with BPF support.
func wsl2EBPFProbe() bool {
	// Check for BPF filesystem mount
	if mounts, err := os.ReadFile("/proc/mounts"); err == nil {
		if strings.Contains(string(mounts), "bpf") {
			return true
		}
	}
	// Check kernel config if available
	for _, configPath := range []string{
		"/proc/config.gz",
		"/boot/config-" + currentKernelRelease(),
	} {
		if fileExists(configPath) {
			return true // presence implies BPF is compiled in
		}
	}
	return false
}

// ─── strace Probe ────────────────────────────────────────────────────────────

func probeStrace() (available bool, version string) {
	out, err := exec.Command("strace", "-V").CombinedOutput()
	if err != nil {
		// strace returns exit code 1 for -V on some versions
		if len(out) > 0 {
			return true, extractStraceVersion(string(out))
		}
		return false, ""
	}
	return true, extractStraceVersion(string(out))
}

func extractStraceVersion(s string) string {
	re := regexp.MustCompile(`strace -- version (\S+)|strace (\d+\.\d+[\.\d]*)`)
	m := re.FindStringSubmatch(s)
	if m == nil {
		return "unknown"
	}
	for _, g := range m[1:] {
		if g != "" {
			return g
		}
	}
	return "unknown"
}

// ─── Capability Checks ───────────────────────────────────────────────────────

func hasCap(capName string) bool {
	// Use capsh if available for accurate capability check
	out, err := exec.Command("capsh", "--print").Output()
	if err == nil {
		return strings.Contains(strings.ToLower(string(out)), capName)
	}
	// Fallback: check /proc/self/status CapEff
	return checkCapFromProcStatus(capName)
}

func checkCapFromProcStatus(capName string) bool {
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			hexStr := strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
			capMask, err := strconv.ParseUint(hexStr, 16, 64)
			if err != nil {
				return false
			}
			// CAP_BPF = 39, CAP_SYS_PTRACE = 19
			capBit := capNameToBit(capName)
			if capBit < 0 {
				return false
			}
			return (capMask>>uint(capBit))&1 == 1
		}
	}
	return false
}

func capNameToBit(name string) int {
	caps := map[string]int{
		"cap_bpf":        39,
		"cap_sys_ptrace": 19,
		"cap_sys_admin":  21,
	}
	return caps[strings.ToLower(name)]
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func pickFallback(r CapabilityReport) schema.SensorBackend {
	if r.StraceAvailable && r.HasCAP_SYS_PTRACE {
		return schema.BackendStrace
	}
	return schema.BackendNone
}

func windowsReport() CapabilityReport {
	return CapabilityReport{
		Backend:         schema.BackendETW,
		EBPFAvailable:   false,
		StraceAvailable: false,
	}
}

func kernelMeetsMin(major, minor, minMajor, minMinor int) bool {
	if major > minMajor {
		return true
	}
	if major == minMajor && minor >= minMinor {
		return true
	}
	return false
}

func parseKernelVersion(version string) (major, minor, patch int) {
	m := kernelVersionRE.FindStringSubmatch(version)
	if len(m) < 4 {
		return 0, 0, 0
	}
	major, _ = strconv.Atoi(m[1])
	minor, _ = strconv.Atoi(m[2])
	patch, _ = strconv.Atoi(m[3])
	return
}

func currentKernelRelease() string {
	out, err := exec.Command("uname", "-r").Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// ApplyToContext stamps capability probe results into a PlatformContext.
func ApplyToContext(ctx *schema.PlatformContext, r CapabilityReport) {
	ctx.Capabilities.ActiveBackend = r.Backend
	ctx.Capabilities.EBPFAvailable = r.EBPFAvailable
	ctx.Capabilities.EBPFKernelMin = r.EBPFPerfBuffer
	ctx.Capabilities.EBPFRingBuffer = r.EBPFRingBuffer
	ctx.Capabilities.StraceAvailable = r.StraceAvailable
}
