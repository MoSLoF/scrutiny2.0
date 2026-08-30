package ebpf

import (
	"testing"

	"github.com/MoSLoF/scrutiny2.0/internal/schema"
)

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
	obs := buildFilesystem(accesses)

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
	obs := buildFilesystem([]FileAccess{{Op: opOpen, Path: ""}})
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

func TestIsInteropPath(t *testing.T) {
	if !isInteropPath("/mnt/c/Windows/System32/evil.exe") {
		t.Error("/mnt/c/... should be an interop path")
	}
	if isInteropPath("/tmp/x") {
		t.Error("/tmp/x should not be an interop path")
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
