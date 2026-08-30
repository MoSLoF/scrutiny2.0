// Package context implements execution environment detection for Scrutiny v2.
//
// Detection hierarchy (evaluated in order):
//
//  1. Wine     — WINELOADER env var or /proc/self/exe path contains wine
//  2. WSL2     — /proc/version contains "WSL2" or virt-detect returns wsl
//  3. WSL1     — /proc/version contains "Microsoft" (WSL1 uses NT kernel string)
//  4. Container — cgroup namespace indicates Docker/Podman/LXC
//  5. Native Linux — all checks clear
//
// Windows detection is compile-time via GOOS — a native Windows binary
// never reaches this file's logic; see detect_windows.go for that path.
package context

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/MoSLoF/scrutiny2.0/internal/schema"
)

var (
	kernelVersionRE = regexp.MustCompile(`Linux version (\S+)`)
	wslBuildRE      = regexp.MustCompile(`WSL2.*?(\d+\.\d+\.\d+[\.\d]*)`)
	wineVersionRE   = regexp.MustCompile(`(\d+\.\d+[\.\d]*)`)
)

// Detect inspects the runtime environment and returns a fully populated
// PlatformContext. This is the first thing Scrutiny calls on startup.
func Detect() (schema.PlatformContext, error) {
	if runtime.GOOS == "windows" {
		return detectWindows()
	}
	return detectLinux()
}

// detectLinux runs the full detection hierarchy for Linux-based environments.
func detectLinux() (schema.PlatformContext, error) {
	ctx := schema.PlatformContext{
		HostPlatform: "linux",
		InteropLayer: "none",
	}

	procVersion, _ := readFile("/proc/version")
	kernelVersion := extractKernelVersion(procVersion)
	ctx.KernelVersion = kernelVersion
	ctx.OSVersion = readOSRelease()

	// ── 1. Wine detection ────────────────────────────────────────────────
	if wineVersion, isWine := detectWine(); isWine {
		ctx.DetectedPlatform = schema.ContextWine
		ctx.HostPlatform = "linux"
		ctx.InteropLayer = fmt.Sprintf("wine-%s", wineVersion)
		ctx.WineVersion = &wineVersion
		ctx.Capabilities = wineCapabilities()
		return ctx, nil
	}

	// ── 2. WSL2 detection ────────────────────────────────────────────────
	if build, isWSL2 := detectWSL2(procVersion); isWSL2 {
		ctx.DetectedPlatform = schema.ContextWSL2
		ctx.HostPlatform = "windows"
		ctx.InteropLayer = fmt.Sprintf("wsl2-build-%s", build)
		ctx.WSLBuild = &build
		ctx.Capabilities = wsl2Capabilities()
		return ctx, nil
	}

	// ── 3. WSL1 detection ────────────────────────────────────────────────
	if isWSL1 := detectWSL1(procVersion); isWSL1 {
		build := "unknown"
		ctx.DetectedPlatform = schema.ContextWSL1
		ctx.HostPlatform = "windows"
		ctx.InteropLayer = "wsl1"
		ctx.WSLBuild = &build
		ctx.Capabilities = wsl1Capabilities()
		return ctx, nil
	}

	// ── 4. Container detection ───────────────────────────────────────────
	if runtime, isContainer := detectContainer(); isContainer {
		ctx.DetectedPlatform = schema.ContextContainer
		ctx.ContainerRuntime = &runtime
		ctx.Capabilities = containerCapabilities()
		return ctx, nil
	}

	// ── 5. Native Linux ──────────────────────────────────────────────────
	ctx.DetectedPlatform = schema.ContextNativeLinux
	ctx.Capabilities = nativeLinuxCapabilities()
	return ctx, nil
}

// ─── Wine Detection ──────────────────────────────────────────────────────────

func detectWine() (version string, found bool) {
	// Method 1: WINELOADER environment variable
	if wineLoader := os.Getenv("WINELOADER"); wineLoader != "" {
		version = wineVersionFromBinary(wineLoader)
		return version, true
	}

	// Method 2: WINEPREFIX set (process is Wine-managed)
	if os.Getenv("WINEPREFIX") != "" {
		version = wineVersionFromBinary("wine")
		return version, true
	}

	// Method 3: /proc/self/exe path contains wine
	if selfExe, err := os.Readlink("/proc/self/exe"); err == nil {
		if strings.Contains(strings.ToLower(selfExe), "wine") {
			version = wineVersionFromBinary("wine")
			return version, true
		}
	}

	// Method 4: wine binary present AND we're running under it
	// (check parent process cmdline for wine)
	if parentCmd, err := readFile("/proc/1/cmdline"); err == nil {
		if strings.Contains(strings.ToLower(parentCmd), "wine") {
			version = wineVersionFromBinary("wine")
			return version, true
		}
	}

	return "", false
}

func wineVersionFromBinary(winePath string) string {
	out, err := exec.Command(winePath, "--version").Output()
	if err != nil {
		return "unknown"
	}
	m := wineVersionRE.FindString(strings.TrimSpace(string(out)))
	if m == "" {
		return "unknown"
	}
	return m
}

// ─── WSL Detection ───────────────────────────────────────────────────────────

func detectWSL2(procVersion string) (build string, found bool) {
	// WSL2 uses a real Linux kernel — look for WSL2 marker
	if strings.Contains(procVersion, "WSL2") {
		build = extractWSL2Build(procVersion)
		return build, true
	}

	// Secondary: check /proc/sys/kernel/osrelease
	osRelease, _ := readFile("/proc/sys/kernel/osrelease")
	if strings.Contains(osRelease, "WSL2") || strings.Contains(osRelease, "microsoft-standard-WSL2") {
		build = extractWSL2Build(osRelease)
		return build, true
	}

	// Tertiary: systemd-detect-virt if available
	out, err := exec.Command("systemd-detect-virt").Output()
	if err == nil && strings.TrimSpace(string(out)) == "wsl" {
		// Confirm WSL2 vs WSL1 by checking for real Linux kernel
		// WSL1 doesn't have a real Linux kernel version
		if !strings.Contains(procVersion, "Microsoft") {
			build = extractWSL2Build(procVersion)
			return build, true
		}
	}

	return "", false
}

func detectWSL1(procVersion string) bool {
	// WSL1 proxies the NT kernel — /proc/version contains "Microsoft"
	// but NOT "WSL2"
	return strings.Contains(procVersion, "Microsoft") &&
		!strings.Contains(procVersion, "WSL2")
}

func extractWSL2Build(s string) string {
	m := wslBuildRE.FindStringSubmatch(s)
	if len(m) > 1 {
		return m[1]
	}
	// Fall back to kernel version
	return extractKernelVersion(s)
}

// ─── Container Detection ─────────────────────────────────────────────────────

func detectContainer() (runtime string, found bool) {
	// Method 1: /.dockerenv file (Docker)
	if fileExists("/.dockerenv") {
		return "docker", true
	}

	// Method 2: /run/.containerenv (Podman)
	if fileExists("/run/.containerenv") {
		return "podman", true
	}

	// Method 3: cgroup v1 — check for "docker" or "lxc" in cgroup path
	if cgroup, err := readFile("/proc/1/cgroup"); err == nil {
		lower := strings.ToLower(cgroup)
		switch {
		case strings.Contains(lower, "docker"):
			return "docker", true
		case strings.Contains(lower, "lxc"):
			return "lxc", true
		case strings.Contains(lower, "kubepods"):
			return "kubernetes", true
		}
	}

	// Method 4: cgroup v2 — /sys/fs/cgroup/cgroup.controllers exists
	// AND init PID namespace is not the host's
	if fileExists("/sys/fs/cgroup/cgroup.controllers") {
		if nsInode := cgroupNSInode(); nsInode != "" && nsInode != "4026531835" {
			return "container", true
		}
	}

	return "", false
}

// cgroupNSInode is implemented in stat_linux.go (Linux only).

// ─── Capability Maps ─────────────────────────────────────────────────────────

func nativeLinuxCapabilities() schema.SensorCapabilities {
	return schema.SensorCapabilities{
		Syscalls:   schema.SensorFull,
		Network:    schema.SensorFull,
		Filesystem: schema.SensorFull,
		Registry:   schema.SensorUnavailable,
		Memory:     schema.SensorFull,
		InteropFS:  false,
	}
}

func wsl1Capabilities() schema.SensorCapabilities {
	return schema.SensorCapabilities{
		Syscalls:   schema.SensorFull,    // strace works; eBPF does NOT
		Network:    schema.SensorShared,  // shares Windows network stack
		Filesystem: schema.SensorInterop, // /mnt/c accessible
		Registry:   schema.SensorUnavailable,
		Memory:     schema.SensorFull,
		InteropFS:  true,
	}
}

func wsl2Capabilities() schema.SensorCapabilities {
	return schema.SensorCapabilities{
		Syscalls:   schema.SensorFull,      // real Linux kernel — eBPF works
		Network:    schema.SensorForwarded, // ports forwarded from Windows host
		Filesystem: schema.SensorInterop,   // /mnt/c accessible
		Registry:   schema.SensorUnavailable,
		Memory:     schema.SensorFull,
		InteropFS:  true,
	}
}

func wineCapabilities() schema.SensorCapabilities {
	return schema.SensorCapabilities{
		Syscalls:   schema.SensorPartial,  // sees Wine translation layer
		Network:    schema.SensorFull,     // Wine uses host network directly
		Filesystem: schema.SensorInterop,  // Wine virtual FS over Linux FS
		Registry:   schema.SensorEmulated, // Wine registry in ~/.wine
		Memory:     schema.SensorPartial,
		InteropFS:  false,
	}
}

func containerCapabilities() schema.SensorCapabilities {
	return schema.SensorCapabilities{
		Syscalls:   schema.SensorFull, // namespaced but still real
		Network:    schema.SensorFull, // container networking
		Filesystem: schema.SensorNamespaced,
		Registry:   schema.SensorUnavailable,
		Memory:     schema.SensorFull,
		InteropFS:  false,
	}
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func readFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func extractKernelVersion(procVersion string) string {
	m := kernelVersionRE.FindStringSubmatch(procVersion)
	if len(m) > 1 {
		return m[1]
	}
	return "unknown"
}

func readOSRelease() string {
	for _, candidate := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		content, err := readFile(candidate)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(content, "\n") {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				return strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"`)
			}
		}
	}
	return "unknown"
}

// WindowsPathFromWSL converts a /mnt/c/ style path to C:\ for reporting.
func WindowsPathFromWSL(path string) string {
	if !strings.HasPrefix(path, "/mnt/") {
		return path
	}
	parts := strings.SplitN(strings.TrimPrefix(path, "/mnt/"), "/", 2)
	if len(parts) == 0 {
		return path
	}
	drive := strings.ToUpper(parts[0]) + ":\\"
	if len(parts) == 2 {
		return drive + filepath.FromSlash(parts[1])
	}
	return drive
}

// IsInteropPath returns true for paths that cross the WSL/Wine boundary.
func IsInteropPath(path string, ctx schema.PlatformContext) bool {
	switch ctx.DetectedPlatform {
	case schema.ContextWSL1, schema.ContextWSL2:
		return strings.HasPrefix(path, "/mnt/")
	case schema.ContextWine:
		winePrefix := os.Getenv("WINEPREFIX")
		if winePrefix == "" {
			winePrefix = filepath.Join(os.Getenv("HOME"), ".wine")
		}
		return strings.HasPrefix(path, winePrefix+"/drive_c") ||
			strings.HasPrefix(path, winePrefix+"/dosdevices")
	}
	return false
}
