// Package procfs collects a process's lineage and memory behavior from /proc:
// children it spawns, privilege transitions, and — the flagship signal —
// anonymous executable memory regions (rwx), the classic in-memory injection /
// unpacked-shellcode footprint. This is the poll-based process/memory backend;
// the pure parsing lives in this file so it can be unit tested on any platform.
// The /proc-reading collectors are in collector_linux.go.
package procfs

import (
	"strconv"
	"strings"

	"github.com/MoSLoF/scrutiny2.0/internal/schema"
)

// largeAllocBytes is the threshold above which an anonymous writable mapping is
// recorded as a large allocation (packers/loaders often carve out big rwx or
// rw- regions before executing staged code).
const largeAllocBytes = 100 * 1024 * 1024 // 100 MiB

// parseMaps parses the contents of /proc/<pid>/maps and returns: anonymous
// executable regions (rwx marked Suspicious — writable+executable anonymous
// memory is the hallmark of injected code; legitimate code is r-x from a file),
// the set of file-backed mapped paths, and the sizes of large anonymous
// writable allocations.
func parseMaps(data string) ([]schema.MemoryRegion, []string, []int64) {
	var regions []schema.MemoryRegion
	var mapped []string
	var large []int64
	seenFile := map[string]bool{}

	for _, line := range strings.Split(data, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		addrRange := fields[0]
		perms := fields[1]
		if len(perms) < 4 {
			continue
		}
		exec := perms[2] == 'x'
		write := perms[1] == 'w'

		pathname := ""
		if len(fields) >= 6 {
			pathname = strings.Join(fields[5:], " ")
		}
		anon := anonymousMapping(pathname)

		if !anon && strings.HasPrefix(pathname, "/") {
			if !seenFile[pathname] {
				seenFile[pathname] = true
				mapped = append(mapped, pathname)
			}
		}
		// Record executable regions that are effectively anonymous, or that are
		// writable+executable (rwx) regardless of backing — legitimate code is
		// r-x from a real file, so rwx is the injection signature either way.
		if exec && (anon || write) {
			backedBy := "file"
			if anon {
				backedBy = "anonymous"
			}
			regions = append(regions, schema.MemoryRegion{
				AddressRange: addrRange,
				BackedBy:     backedBy,
				Suspicious:   write, // rwx
			})
		}
		if anon && write {
			if sz := regionSize(addrRange); sz >= largeAllocBytes {
				large = append(large, sz)
			}
		}
	}
	return regions, mapped, large
}

// anonymousMapping reports whether a maps pathname denotes memory with no real
// file behind it. Besides the obvious empty/bracketed cases ([heap], [stack],
// [vdso], [anon:...]), this treats deleted-file mappings and the pseudo-devices
// used for anonymous/executable memory as anonymous: a `(deleted)` suffix,
// /dev/zero (how MAP_ANONYMOUS|MAP_SHARED is often reported), /dev/shm, and
// memfd: — the exact backings in-memory injection (memfd_create, deleted-file
// exec, shared-memory shellcode) hides behind.
func anonymousMapping(pathname string) bool {
	if pathname == "" || strings.HasPrefix(pathname, "[") {
		return true
	}
	if strings.HasSuffix(pathname, "(deleted)") {
		return true
	}
	for _, p := range []string{"/dev/zero", "/dev/shm/", "/memfd:", "memfd:", "anon_inode:"} {
		if strings.HasPrefix(pathname, p) {
			return true
		}
	}
	return false
}

// regionSize returns the byte size of a "start-end" hex address range.
func regionSize(addrRange string) int64 {
	dash := strings.IndexByte(addrRange, '-')
	if dash < 0 {
		return 0
	}
	start, err1 := strconv.ParseUint(addrRange[:dash], 16, 64)
	end, err2 := strconv.ParseUint(addrRange[dash+1:], 16, 64)
	if err1 != nil || err2 != nil || end < start {
		return 0
	}
	return int64(end - start)
}

// parseStatusEUID extracts the effective UID (the second value on the "Uid:"
// line: real, effective, saved, fs).
func parseStatusEUID(data string) (int, bool) {
	for _, line := range strings.Split(data, "\n") {
		if strings.HasPrefix(line, "Uid:") {
			f := strings.Fields(line)
			if len(f) >= 3 {
				if euid, err := strconv.Atoi(f[2]); err == nil {
					return euid, true
				}
			}
		}
	}
	return 0, false
}

// parseStatusKB extracts a VmXXX value (in kB) from /proc/<pid>/status, e.g.
// parseStatusKB(data, "VmHWM") for peak resident set size.
func parseStatusKB(data, key string) int64 {
	prefix := key + ":"
	for _, line := range strings.Split(data, "\n") {
		if strings.HasPrefix(line, prefix) {
			f := strings.Fields(line)
			if len(f) >= 2 {
				if v, err := strconv.ParseInt(f[1], 10, 64); err == nil {
					return v
				}
			}
		}
	}
	return 0
}
