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
	a.AddRun(syscalls("read", "write"), nil, nil)
	a.AddRun(syscalls("read", "openat"), nil, nil)

	sys, _, _, _ := a.Build()
	for _, want := range []string{"read", "write", "openat"} {
		if _, ok := sys.Observed[want]; !ok {
			t.Errorf("merged baseline missing %q", want)
		}
	}
	if got := sys.Observed["read"].Count; got != 2 {
		t.Errorf("read count = %d, want 2 (summed across runs)", got)
	}
	if a.Runs() != 2 {
		t.Errorf("runs = %d, want 2", a.Runs())
	}
}

func TestConfidence(t *testing.T) {
	cases := map[int]schema.BaselineConfidence{
		1: schema.ConfidenceLow,
		2: schema.ConfidenceMedium,
		3: schema.ConfidenceHigh,
		5: schema.ConfidenceHigh,
	}
	for runs, want := range cases {
		if got := Confidence(runs); got != want {
			t.Errorf("Confidence(%d) = %s, want %s", runs, got, want)
		}
	}
}

func TestVarianceNotes_FlagsUnstableSyscalls(t *testing.T) {
	a := New()
	a.AddRun(syscalls("read", "write"), nil, nil)
	a.AddRun(syscalls("read", "write"), nil, nil)
	a.AddRun(syscalls("read", "write", "ptrace"), nil, nil) // ptrace only in run 3

	_, _, _, notes := a.Build()
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
	a.AddRun(syscalls("read"), nil, nil)
	_, _, _, notes := a.Build()
	if len(notes) != 0 {
		t.Errorf("single run should have no variance notes, got %v", notes)
	}
}

func TestAddRun_UnionsNetworkPorts(t *testing.T) {
	a := New()
	a.AddRun(nil, &schema.NetworkObservation{
		ListeningPorts: []schema.ListeningPort{{Proto: "tcp", Address: "0.0.0.0", Port: 80}},
	}, nil)
	a.AddRun(nil, &schema.NetworkObservation{
		ListeningPorts: []schema.ListeningPort{
			{Proto: "tcp", Address: "0.0.0.0", Port: 80},
			{Proto: "tcp", Address: "0.0.0.0", Port: 8080},
		},
	}, nil)

	_, net, _, notes := a.Build()
	if len(net.ListeningPorts) != 2 {
		t.Fatalf("listening ports = %d, want 2 (union)", len(net.ListeningPorts))
	}
	// Port 8080 appeared in only 1 of 2 runs — should be flagged unstable.
	if !strings.Contains(strings.Join(notes, "\n"), "tcp/8080 (1/2)") {
		t.Errorf("expected variance note for tcp/8080, got %v", notes)
	}
}

func TestAddRun_MergesFilesystemCounts(t *testing.T) {
	fs := func(path string, count int) *schema.FilesystemObservation {
		return &schema.FilesystemObservation{
			PathsWritten: []schema.FilePath{{Path: path, NormalizedPath: path, Count: count}},
		}
	}
	a := New()
	a.AddRun(nil, nil, fs("/tmp/x", 2))
	a.AddRun(nil, nil, fs("/tmp/x", 3))

	_, _, out, _ := a.Build()
	if len(out.PathsWritten) != 1 {
		t.Fatalf("written paths = %d, want 1 (deduped)", len(out.PathsWritten))
	}
	if out.PathsWritten[0].Count != 5 {
		t.Errorf("write count = %d, want 5 (summed)", out.PathsWritten[0].Count)
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
	}, nil)
	a.AddRun(nil, &schema.NetworkObservation{
		RawSockets: []schema.RawSocket{{Family: "packet", Protocol: "0x0003", Interface: "*"}},
	}, nil) // second run: same raw socket, promiscuous interface NOT observed again

	_, net, _, notes := a.Build()
	if len(net.RawSockets) != 1 {
		t.Fatalf("raw sockets = %d, want 1 (deduped)", len(net.RawSockets))
	}
	if len(net.PromiscuousInterfaces) != 1 || net.PromiscuousInterfaces[0] != "eth0" {
		t.Errorf("promiscuous interfaces = %v, want [eth0]", net.PromiscuousInterfaces)
	}
	// eth0 was promiscuous in only 1 of 2 runs — union keeps it, but it's
	// worth confirming it doesn't silently disappear either way.
	_ = notes
}
