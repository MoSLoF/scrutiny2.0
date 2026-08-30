package baseline

import (
	"strings"
	"testing"

	"github.com/MoSLoF/scrutiny2.0/internal/schema"
)

func syscalls(names ...string) *schema.SyscallsObservation {
	o := &schema.SyscallsObservation{Observed: map[string]schema.SyscallRecord{}}
	for _, n := range names {
		o.Observed[n] = schema.SyscallRecord{Count: 1}
	}
	return o
}

func TestAddRun_UnionsSyscallsAndSumsCounts(t *testing.T) {
	a := New()
	a.AddRun(syscalls("read", "write"), nil, nil, nil, nil)
	a.AddRun(syscalls("read", "openat"), nil, nil, nil, nil)

	r := a.Build()
	for _, want := range []string{"read", "write", "openat"} {
		if _, ok := r.Syscalls.Observed[want]; !ok {
			t.Errorf("merged baseline missing %q", want)
		}
	}
	if got := r.Syscalls.Observed["read"].Count; got != 2 {
		t.Errorf("read count = %d, want 2 (summed across runs)", got)
	}
	if a.Runs() != 2 {
		t.Errorf("runs = %d, want 2", a.Runs())
	}
}

func TestConfidence(t *testing.T) {
	cases := []struct {
		runs     int
		variance bool
		want     schema.BaselineConfidence
	}{
		{1, false, schema.ConfidenceLow},
		{2, false, schema.ConfidenceMedium},
		{3, false, schema.ConfidenceHigh},
		{5, false, schema.ConfidenceHigh},
		// Variance caps an otherwise-high confidence at medium — a baseline
		// whose runs disagree isn't "consistent" no matter the run count.
		{3, true, schema.ConfidenceMedium},
		{5, true, schema.ConfidenceMedium},
		// Variance can't lift confidence, only cap it.
		{1, true, schema.ConfidenceLow},
	}
	for _, tc := range cases {
		if got := Confidence(tc.runs, tc.variance); got != tc.want {
			t.Errorf("Confidence(%d, variance=%v) = %s, want %s", tc.runs, tc.variance, got, tc.want)
		}
	}
}

func TestVarianceNotes_FlagsUnstableSyscalls(t *testing.T) {
	a := New()
	a.AddRun(syscalls("read", "write"), nil, nil, nil, nil)
	a.AddRun(syscalls("read", "write"), nil, nil, nil, nil)
	a.AddRun(syscalls("read", "write", "ptrace"), nil, nil, nil, nil) // ptrace only in run 3

	notes := a.Build().Notes
	joined := strings.Join(notes, "\n")
	if !strings.Contains(joined, "ptrace (1/3)") {
		t.Errorf("expected variance note for ptrace (1/3), got:\n%s", joined)
	}
	if strings.Contains(joined, "read (") || strings.Contains(joined, "write (") {
		t.Errorf("stable syscalls should not be flagged, got:\n%s", joined)
	}
}

func TestVarianceNotes_NoneForSingleRun(t *testing.T) {
	a := New()
	a.AddRun(syscalls("read"), nil, nil, nil, nil)
	if notes := a.Build().Notes; len(notes) != 0 {
		t.Errorf("single run should have no variance notes, got %v", notes)
	}
}

func TestAddRun_UnionsNetworkPorts(t *testing.T) {
	a := New()
	a.AddRun(nil, &schema.NetworkObservation{
		ListeningPorts: []schema.ListeningPort{{Proto: "tcp", Address: "0.0.0.0", Port: 80}},
	}, nil, nil, nil)
	a.AddRun(nil, &schema.NetworkObservation{
		ListeningPorts: []schema.ListeningPort{
			{Proto: "tcp", Address: "0.0.0.0", Port: 80},
			{Proto: "tcp", Address: "0.0.0.0", Port: 8080},
		},
	}, nil, nil, nil)

	r := a.Build()
	if len(r.Network.ListeningPorts) != 2 {
		t.Fatalf("listening ports = %d, want 2 (union)", len(r.Network.ListeningPorts))
	}
	// Port 8080 appeared in only 1 of 2 runs — should be flagged unstable.
	if !strings.Contains(strings.Join(r.Notes, "\n"), "tcp/8080 (1/2)") {
		t.Errorf("expected variance note for tcp/8080, got %v", r.Notes)
	}
}

func TestAddRun_MergesFilesystemCounts(t *testing.T) {
	fs := func(path string, count int) *schema.FilesystemObservation {
		return &schema.FilesystemObservation{
			PathsWritten: []schema.FilePath{{Path: path, NormalizedPath: path, Count: count}},
		}
	}
	a := New()
	a.AddRun(nil, nil, fs("/tmp/x", 2), nil, nil)
	a.AddRun(nil, nil, fs("/tmp/x", 3), nil, nil)

	r := a.Build()
	if len(r.Filesystem.PathsWritten) != 1 {
		t.Fatalf("written paths = %d, want 1 (deduped)", len(r.Filesystem.PathsWritten))
	}
	if r.Filesystem.PathsWritten[0].Count != 5 {
		t.Errorf("write count = %d, want 5 (summed)", r.Filesystem.PathsWritten[0].Count)
	}
}

// TestAddRun_UnionsRawSocketsAndPromiscuousInterfaces is a regression test:
// the Accumulator originally only handled ListeningPorts/OutboundConnections
// from NetworkObservation, so RawSockets and PromiscuousInterfaces silently
// vanished from any baseline captured with --runs > 1.
func TestAddRun_UnionsRawSocketsAndPromiscuousInterfaces(t *testing.T) {
	a := New()
	a.AddRun(nil, &schema.NetworkObservation{
		RawSockets:            []schema.RawSocket{{Family: "packet", Protocol: "0x0003", Interface: "*"}},
		PromiscuousInterfaces: []string{"eth0"},
	}, nil, nil, nil)
	a.AddRun(nil, &schema.NetworkObservation{
		RawSockets: []schema.RawSocket{{Family: "packet", Protocol: "0x0003", Interface: "*"}},
	}, nil, nil, nil) // second run: same raw socket, promiscuous interface NOT observed again

	r := a.Build()
	if len(r.Network.RawSockets) != 1 {
		t.Fatalf("raw sockets = %d, want 1 (deduped)", len(r.Network.RawSockets))
	}
	if len(r.Network.PromiscuousInterfaces) != 1 || r.Network.PromiscuousInterfaces[0] != "eth0" {
		t.Errorf("promiscuous interfaces = %v, want [eth0]", r.Network.PromiscuousInterfaces)
	}
}

// TestAddRun_UnionsProcessAndMemory is the same class of regression guard for
// the process and memory dimensions: without it, a --runs>1 baseline would
// silently drop children, privilege changes, and executable memory regions.
func TestAddRun_UnionsProcessAndMemory(t *testing.T) {
	a := New()
	a.AddRun(nil, nil, nil,
		&schema.ProcessObservation{
			ChildrenSpawned:  []schema.ChildProcess{{Name: "sh", Path: "/bin/sh", UID: 1000}},
			PrivilegeChanges: []schema.PrivilegeChange{{FromUID: 1000, ToUID: 0, Syscall: "setuid"}},
		},
		&schema.MemoryObservation{
			PeakRSSKB:         1000,
			ExecutableRegions: []schema.MemoryRegion{{AddressRange: "aaaa-bbbb", BackedBy: "anonymous", Suspicious: true}},
			MappedFiles:       []string{"/lib/libc.so.6"},
		})
	a.AddRun(nil, nil, nil,
		&schema.ProcessObservation{
			ChildrenSpawned: []schema.ChildProcess{{Name: "curl", Path: "/usr/bin/curl", UID: 1000}},
		},
		&schema.MemoryObservation{PeakRSSKB: 2048}) // higher peak

	r := a.Build()
	if len(r.Process.ChildrenSpawned) != 2 {
		t.Errorf("children = %d, want 2 (union of both runs)", len(r.Process.ChildrenSpawned))
	}
	if len(r.Process.PrivilegeChanges) != 1 {
		t.Errorf("privilege changes = %d, want 1", len(r.Process.PrivilegeChanges))
	}
	if len(r.Memory.ExecutableRegions) != 1 || !r.Memory.ExecutableRegions[0].Suspicious {
		t.Errorf("exec regions = %+v, want 1 suspicious", r.Memory.ExecutableRegions)
	}
	if r.Memory.PeakRSSKB != 2048 {
		t.Errorf("peak RSS = %d, want 2048 (max across runs)", r.Memory.PeakRSSKB)
	}
}
