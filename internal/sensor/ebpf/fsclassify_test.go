package ebpf

import (
	"testing"

	"github.com/MoSLoF/scrutiny2.0/internal/schema"
)

var nativeLinuxCtx = schema.PlatformContext{DetectedPlatform: schema.ContextNativeLinux}

func TestBucketsFor(t *testing.T) {
	cases := []struct {
		name string
		a    FileAccess
		want []int
	}{
		{"read-only open", FileAccess{Op: opOpen, Flags: 0}, []int{bucketRead}},
		{"write open", FileAccess{Op: opOpen, Flags: fWRONLY}, []int{bucketWritten}},
		{"create+write open", FileAccess{Op: opOpen, Flags: fCREAT | fWRONLY}, []int{bucketCreated, bucketWritten}},
		{"truncate counts as write", FileAccess{Op: opOpen, Flags: fTRUNC}, []int{bucketWritten}},
		{"delete", FileAccess{Op: opDelete}, []int{bucketDeleted}},
		{"exec", FileAccess{Op: opExec}, []int{bucketExec}},
		{"rename dest", FileAccess{Op: opRename}, []int{bucketCreated, bucketWritten}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := bucketsFor(tc.a)
			if len(got) != len(tc.want) {
				t.Fatalf("buckets = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("buckets = %v, want %v", got, tc.want)
				}
			}
		})
	}
}

func TestBuildFilesystem_DropperAppearsWrittenAndExec(t *testing.T) {
	// A classic dropper: create+write /tmp/payload, then execute it.
	accesses := []FileAccess{
		{Op: opOpen, Flags: fCREAT | fWRONLY, Path: "/tmp/payload"},
		{Op: opOpen, Flags: fCREAT | fWRONLY, Path: "/tmp/payload"}, // written twice
		{Op: opExec, Path: "/tmp/payload"},
		{Op: opOpen, Flags: 0, Path: "/etc/ld.so.cache"}, // benign read
	}
	obs := buildFilesystem(accesses, nativeLinuxCtx)

	if !containsPath(obs.PathsCreated, "/tmp/payload") {
		t.Error("/tmp/payload should be in PathsCreated")
	}
	if !containsPath(obs.PathsWritten, "/tmp/payload") {
		t.Error("/tmp/payload should be in PathsWritten")
	}
	if !containsPath(obs.ExecsTouched, "/tmp/payload") {
		t.Error("/tmp/payload should be in ExecsTouched (dropper signature)")
	}
	if !containsPath(obs.PathsRead, "/etc/ld.so.cache") {
		t.Error("/etc/ld.so.cache should be in PathsRead")
	}
	// The write count should reflect both create+write opens.
	for _, f := range obs.PathsWritten {
		if f.Path == "/tmp/payload" && f.Count != 2 {
			t.Errorf("write count = %d, want 2", f.Count)
		}
	}
}

func TestBuildFilesystem_EmptyPathsIgnored(t *testing.T) {
	obs := buildFilesystem([]FileAccess{{Op: opOpen, Path: ""}}, nativeLinuxCtx)
	if fileTotal(obs) != 0 {
		t.Errorf("empty-path access should be ignored, got %d entries", fileTotal(obs))
	}
}

func TestIsSensitivePath(t *testing.T) {
	sensitive := []string{
		"/etc/shadow", "/etc/passwd", "/etc/sudoers",
		"/home/user/.ssh/id_rsa", "/root/.bash_history", "/home/u/.aws/credentials",
	}
	for _, p := range sensitive {
		if !isSensitivePath(p) {
			t.Errorf("%q should be sensitive", p)
		}
	}
	for _, p := range []string{"/tmp/x", "/home/user/notes.txt", "/usr/bin/ls"} {
		if isSensitivePath(p) {
			t.Errorf("%q should NOT be sensitive", p)
		}
	}
}

// TestBuildFilesystem_InteropPathIsContextAware is a regression test.
// buildFilesystem used to call a bare "/mnt/"-prefix check regardless of
// platform, so a Wine interop write was NEVER flagged — Wine's interop
// boundary is ~/.wine/drive_c, not /mnt/. It now defers to
// context.IsInteropPath, which knows the difference per platform.
func TestBuildFilesystem_InteropPathIsContextAware(t *testing.T) {
	t.Setenv("WINEPREFIX", "/home/hb/.wine")

	wineCtx := schema.PlatformContext{DetectedPlatform: schema.ContextWine}
	wsl2Ctx := schema.PlatformContext{DetectedPlatform: schema.ContextWSL2}

	wineAccess := []FileAccess{
		{Op: opOpen, Flags: fWRONLY, Path: "/home/hb/.wine/drive_c/windows/system32/evil.dll"},
	}
	if obs := buildFilesystem(wineAccess, wineCtx); !obs.PathsWritten[0].InteropPath {
		t.Error("Wine drive_c write should be flagged interop under a Wine context")
	}
	// Same path shape evaluated under WSL2 (where it means nothing special)
	// must NOT be flagged — proves this is genuinely platform-aware, not
	// just a wider prefix match.
	if obs := buildFilesystem(wineAccess, wsl2Ctx); obs.PathsWritten[0].InteropPath {
		t.Error("a Wine-shaped path should not be flagged interop under a WSL2 context")
	}

	wslAccess := []FileAccess{
		{Op: opOpen, Flags: fWRONLY, Path: "/mnt/c/Windows/System32/evil.exe"},
	}
	if obs := buildFilesystem(wslAccess, wsl2Ctx); !obs.PathsWritten[0].InteropPath {
		t.Error("/mnt/c/... write should still be flagged interop under WSL2")
	}
}

func containsPath(list []schema.FilePath, path string) bool {
	for _, f := range list {
		if f.Path == path {
			return true
		}
	}
	return false
}

func fileTotal(obs *schema.FilesystemObservation) int {
	return len(obs.PathsRead) + len(obs.PathsWritten) + len(obs.PathsCreated) +
		len(obs.PathsDeleted) + len(obs.ExecsTouched)
}
