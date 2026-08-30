//go:build windows

package context

import (
	"os/exec"
	"runtime"
	"strings"

	"github.com/MoSLoF/scrutiny2.0/internal/schema"
)

func detectWindows() (schema.PlatformContext, error) {
	ctx := schema.PlatformContext{
		DetectedPlatform: schema.ContextNativeWindows,
		HostPlatform:     "windows",
		InteropLayer:     "none",
		KernelVersion:    windowsKernelVersion(),
		OSVersion:        windowsOSVersion(),
	}
	ctx.Capabilities = windowsCapabilities()
	return ctx, nil
}

func windowsCapabilities() schema.SensorCapabilities {
	sysmonAvail := isSysmonAvailable()
	syscallAvail := schema.SensorUnavailable
	if sysmonAvail {
		syscallAvail = schema.SensorPartial
	}
	return schema.SensorCapabilities{
		Syscalls:        syscallAvail,
		Network:         schema.SensorFull,
		Filesystem:      schema.SensorFull,
		Registry:        schema.SensorNative,
		Memory:          schema.SensorPartial,
		InteropFS:       false,
		EBPFAvailable:   false,
		StraceAvailable: false,
	}
}

func isSysmonAvailable() bool {
	for _, svc := range []string{"Sysmon64", "Sysmon"} {
		out, err := exec.Command("sc", "query", svc).Output()
		if err == nil && strings.Contains(string(out), "RUNNING") {
			return true
		}
	}
	return false
}

func windowsKernelVersion() string {
	out, err := exec.Command("cmd", "/c", "ver").Output()
	if err != nil {
		return runtime.GOOS + "/" + runtime.GOARCH
	}
	return strings.TrimSpace(string(out))
}

func windowsOSVersion() string {
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		"(Get-CimInstance Win32_OperatingSystem).Caption").Output()
	if err != nil {
		return "Windows (unknown version)"
	}
	return strings.TrimSpace(string(out))
}

// cgroupNSInode is not applicable on Windows — stub satisfies compiler.
func cgroupNSInode() string { return "" }
