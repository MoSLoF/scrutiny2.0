package strace

import (
	"testing"

	"github.com/MoSLoF/scrutiny2.0/internal/schema"
)

func TestParseLine_NormalSyscall(t *testing.T) {
	e, ok := parseLine(`3812 1712345678.123456 openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3 <0.000012>`)
	if !ok {
		t.Fatal("expected a parsed event")
	}
	if e.name != "openat" {
		t.Errorf("name = %q, want openat", e.name)
	}
	if e.isError {
		t.Error("should not be an error")
	}
	if e.latencyNS != 12000 {
		t.Errorf("latency = %d ns, want 12000 (12µs)", e.latencyNS)
	}
	if e.tsMicros != 1712345678123456 {
		t.Errorf("ts = %d, want 1712345678123456", e.tsMicros)
	}
}

func TestParseLine_ErrorReturn(t *testing.T) {
	e, ok := parseLine(`3812 1712345678.200000 openat(AT_FDCWD, "/nope", O_RDONLY) = -1 ENOENT (No such file or directory) <0.000008>`)
	if !ok {
		t.Fatal("expected a parsed event")
	}
	if !e.isError {
		t.Error("ENOENT return should be flagged as an error")
	}
}

func TestParseLine_SkipsNonSyscalls(t *testing.T) {
	skip := []string{
		`3812 1712345678.3 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED} ---`,
		`3812 1712345678.4 +++ exited with 0 +++`,
		`3812 1712345678.5 read(3, <unfinished ...>`,
		``,
	}
	for _, line := range skip {
		if _, ok := parseLine(line); ok {
			t.Errorf("line should be skipped: %q", line)
		}
	}
}

func TestParseLine_ResumedCountsOnce(t *testing.T) {
	// The matching "<... read resumed>" line is the one that counts; the
	// earlier "<unfinished ...>" is skipped, so read is recorded exactly once.
	e, ok := parseLine(`3812 1712345678.6 <... read resumed>"data", 100) = 4 <0.001000>`)
	if !ok {
		t.Fatal("resumed line should parse")
	}
	if e.name != "read" {
		t.Errorf("name = %q, want read", e.name)
	}
	if e.latencyNS != 1_000_000 {
		t.Errorf("latency = %d ns, want 1000000 (1ms)", e.latencyNS)
	}
}

func TestParseLine_NoPidPrefix(t *testing.T) {
	// Without -f, strace omits the leading pid.
	e, ok := parseLine(`1712345678.123456 close(3) = 0 <0.000003>`)
	if !ok || e.name != "close" {
		t.Fatalf("event = %+v ok=%v, want close", e, ok)
	}
}

func TestRecord_AggregatesCountsAndOffsets(t *testing.T) {
	obs := &schema.SyscallsObservation{Observed: map[string]schema.SyscallRecord{}}
	var firstTs int64

	e1, _ := parseLine(`1 1712345678.000000 read(3, "", 100) = 0 <0.000010>`)
	e2, _ := parseLine(`1 1712345678.050000 read(3, "x", 100) = 1 <0.000020>`)
	e3, _ := parseLine(`1 1712345678.100000 write(1, "y", 1) = -1 EBADF (Bad fd) <0.000005>`)
	record(obs, e1, &firstTs)
	record(obs, e2, &firstTs)
	record(obs, e3, &firstTs)

	read := obs.Observed["read"]
	if read.Count != 2 {
		t.Errorf("read count = %d, want 2", read.Count)
	}
	if read.FirstSeenOffsetMS != 0 || read.LastSeenOffsetMS != 50 {
		t.Errorf("read offsets = %d..%d, want 0..50", read.FirstSeenOffsetMS, read.LastSeenOffsetMS)
	}
	if read.MaxLatencyNS != 20000 {
		t.Errorf("read max latency = %d, want 20000", read.MaxLatencyNS)
	}
	write := obs.Observed["write"]
	if write.ErrorCount != 1 {
		t.Errorf("write error count = %d, want 1", write.ErrorCount)
	}
	if write.LastSeenOffsetMS != 100 {
		t.Errorf("write offset = %d, want 100", write.LastSeenOffsetMS)
	}
}
