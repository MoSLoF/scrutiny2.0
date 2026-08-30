package procfs

import (
	"strings"
	"testing"
)

// A representative /proc/<pid>/maps snapshot: normal r-x file-backed code, an
// injected rwx anonymous region (the signal), a benign rw- anonymous heap, and
// a large anonymous writable allocation.
const sampleMaps = `55a4c0000000-55a4c0021000 r-xp 00000000 08:01 131079 /usr/bin/target
55a4c0021000-55a4c0022000 r--p 00021000 08:01 131079 /usr/bin/target
7f2a00000000-7f2a00001000 rwxp 00000000 00:00 0
7f2a10000000-7f2a10021000 rw-p 00000000 00:00 0 [heap]
7f2a20000000-7f2a28000000 rw-p 00000000 00:00 0
7f2a30000000-7f2a30100000 r-xp 00000000 08:01 200000 /lib/x86_64-linux-gnu/libc.so.6
`

func TestParseMaps_FlagsAnonymousRWX(t *testing.T) {
	regions, mapped, large := parseMaps(sampleMaps)

	// Only the anonymous executable region should be recorded, and it's rwx.
	if len(regions) != 1 {
		t.Fatalf("executable regions = %d, want 1 (only the anonymous exec one)", len(regions))
	}
	if regions[0].BackedBy != "anonymous" || !regions[0].Suspicious {
		t.Errorf("region = %+v, want anonymous + suspicious (rwx)", regions[0])
	}

	// File-backed mappings are collected, deduped.
	wantFiles := map[string]bool{"/usr/bin/target": true, "/lib/x86_64-linux-gnu/libc.so.6": true}
	if len(mapped) != len(wantFiles) {
		t.Errorf("mapped files = %v, want %d entries", mapped, len(wantFiles))
	}
	for _, f := range mapped {
		if !wantFiles[f] {
			t.Errorf("unexpected mapped file %q", f)
		}
	}

	// The 128 MiB anonymous writable region exceeds the large-alloc threshold.
	if len(large) != 1 {
		t.Fatalf("large allocations = %v, want 1", large)
	}
	if large[0] != 0x8000000 {
		t.Errorf("large alloc size = %d, want %d", large[0], 0x8000000)
	}
}

func TestParseMaps_NoFalsePositiveOnNormalProcess(t *testing.T) {
	const normal = `55a4c0000000-55a4c0021000 r-xp 00000000 08:01 131079 /usr/bin/target
7f2a10000000-7f2a10021000 rw-p 00000000 00:00 0 [heap]
7ffd00000000-7ffd00021000 rw-p 00000000 00:00 0 [stack]
`
	regions, _, large := parseMaps(normal)
	if len(regions) != 0 {
		t.Errorf("executable regions = %d, want 0 (no anonymous exec)", len(regions))
	}
	if len(large) != 0 {
		t.Errorf("large allocations = %d, want 0", len(large))
	}
}

// Real injection rarely shows a blank pathname: MAP_ANONYMOUS|MAP_SHARED is
// reported as /dev/zero, and memfd/deleted-file exec mappings carry a pseudo
// path that still starts with "/". These must classify as anonymous.
func TestParseMaps_PseudoPathExecIsAnonymous(t *testing.T) {
	const maps = `796813158000-796813159000 rwxs 00000000 00:01 6167 /dev/zero (deleted)
7f0000000000-7f0000001000 r-xp 00000000 08:01 999 /memfd:jit (deleted)
55a4c0000000-55a4c0021000 r-xp 00000000 08:01 131079 /usr/bin/target
`
	regions, mapped, _ := parseMaps(maps)

	// The rwx /dev/zero region must be recorded, anonymous, and suspicious.
	var foundRWX bool
	for _, r := range regions {
		if r.AddressRange == "796813158000-796813159000" {
			foundRWX = true
			if r.BackedBy != "anonymous" || !r.Suspicious {
				t.Errorf("/dev/zero rwx region = %+v, want anonymous + suspicious", r)
			}
		}
	}
	if !foundRWX {
		t.Error("rwx /dev/zero (deleted) region was not captured (the injection blind spot)")
	}
	// Pseudo paths must not leak into MappedFiles; only the real binary should.
	for _, f := range mapped {
		if strings.Contains(f, "/dev/zero") || strings.Contains(f, "memfd") {
			t.Errorf("pseudo path %q should not be a mapped file", f)
		}
	}
	if len(mapped) != 1 || mapped[0] != "/usr/bin/target" {
		t.Errorf("mapped files = %v, want [/usr/bin/target]", mapped)
	}
}

func TestParseStatusEUID(t *testing.T) {
	const status = `Name:	target
Uid:	1000	1000	1000	1000
Gid:	1000	1000	1000	1000
`
	euid, ok := parseStatusEUID(status)
	if !ok || euid != 1000 {
		t.Errorf("euid = %d ok=%v, want 1000 true", euid, ok)
	}

	const rooted = `Uid:	1000	0	0	0
`
	euid, ok = parseStatusEUID(rooted)
	if !ok || euid != 0 {
		t.Errorf("euid = %d ok=%v, want 0 true (setuid-root)", euid, ok)
	}
}

func TestParseStatusKB(t *testing.T) {
	const status = `VmPeak:	  123456 kB
VmRSS:	   65432 kB
VmHWM:	   99999 kB
`
	if got := parseStatusKB(status, "VmHWM"); got != 99999 {
		t.Errorf("VmHWM = %d, want 99999", got)
	}
	if got := parseStatusKB(status, "VmRSS"); got != 65432 {
		t.Errorf("VmRSS = %d, want 65432", got)
	}
	if got := parseStatusKB(status, "VmMissing"); got != 0 {
		t.Errorf("missing key = %d, want 0", got)
	}
}
