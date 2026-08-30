package analysis

import (
	"fmt"
	"testing"

	"github.com/MoSLoF/scrutiny2.0/internal/schema"
)

// baseWith builds a native-Linux baseline whose observed syscall set is the
// given names.
func baseWith(observed ...string) *schema.Baseline {
	p := schema.PlatformContext{DetectedPlatform: schema.ContextNativeLinux}
	b := schema.NewBaseline(p, schema.TargetProcess{Name: "test"})
	for _, s := range observed {
		b.Syscalls.Observed[s] = schema.SyscallRecord{Count: 1}
	}
	return b
}

// obsWith builds an observation linked to b, sharing its platform, whose
// observed syscall set is the given names.
func obsWith(b *schema.Baseline, observed ...string) *schema.Observation {
	o := schema.NewObservation(b.Scrutiny.BaselineID, b.Scrutiny.Platform, schema.TargetProcess{Name: "test"})
	for _, s := range observed {
		o.Syscalls.Observed[s] = schema.SyscallRecord{Count: 1}
	}
	return o
}

func TestClean_NoDeviation(t *testing.T) {
	b := baseWith("read", "write", "openat")
	o := obsWith(b, "read", "write") // strict subset — nothing new
	r := Analyze(b, o)

	if r.Verdict != schema.VerdictClean {
		t.Errorf("verdict = %s, want clean", r.Verdict)
	}
	if r.RiskScore != 0 {
		t.Errorf("risk score = %d, want 0", r.RiskScore)
	}
	if len(r.Anomalies) != 0 {
		t.Errorf("anomalies = %d, want 0", len(r.Anomalies))
	}
	if !r.ContextMatch {
		t.Error("context should match")
	}
}

func TestSuspiciousSyscall_IsCriticalAndMalicious(t *testing.T) {
	b := baseWith("read", "write")
	o := obsWith(b, "read", "ptrace") // ptrace is in SuspiciousNeverExpected
	r := Analyze(b, o)

	if r.Verdict != schema.VerdictMalicious {
		t.Fatalf("verdict = %s, want malicious", r.Verdict)
	}
	var found *schema.Anomaly
	for i := range r.Anomalies {
		if r.Anomalies[i].ObservedValue == "ptrace" {
			found = &r.Anomalies[i]
		}
	}
	if found == nil {
		t.Fatal("no anomaly reported for ptrace")
	}
	if found.Severity != schema.SeverityCritical {
		t.Errorf("ptrace severity = %s, want critical", found.Severity)
	}
	if found.MITRETechnique == "" {
		t.Error("ptrace anomaly missing MITRE technique mapping")
	}
	if r.Summary.BySeverity.Critical < 1 {
		t.Error("summary should count the critical anomaly")
	}
}

func TestBenignSyscall_IsSuppressed(t *testing.T) {
	b := baseWith("read")
	o := obsWith(b, "read", "mmap") // mmap is a default high-frequency benign syscall
	r := Analyze(b, o)

	if r.RiskScore != 0 {
		t.Errorf("risk score = %d, want 0 (mmap suppressed)", r.RiskScore)
	}
	if r.Verdict != schema.VerdictClean {
		t.Errorf("verdict = %s, want clean", r.Verdict)
	}
	if len(r.Anomalies) != 1 {
		t.Fatalf("anomalies = %d, want 1 (surfaced but suppressed)", len(r.Anomalies))
	}
	if !r.Anomalies[0].Suppressed {
		t.Error("mmap anomaly should be suppressed")
	}
	if r.Anomalies[0].SuppressionReason == nil {
		t.Error("suppressed anomaly should carry a reason")
	}
	if r.Summary.TotalAnomalies != 0 {
		t.Errorf("summary total = %d, want 0 (suppressed excluded from rollup)", r.Summary.TotalAnomalies)
	}
}

func TestNewListeningPort_Network(t *testing.T) {
	b := baseWith("read")
	o := obsWith(b, "read")
	o.Network.ListeningPorts = []schema.ListeningPort{{Port: 4444, Proto: "tcp", Address: "0.0.0.0"}}
	r := Analyze(b, o)

	if r.Verdict != schema.VerdictSuspicious {
		t.Errorf("verdict = %s, want suspicious (new port is high severity)", r.Verdict)
	}
	if r.Summary.ByDimension[schema.DimNetwork] != 1 {
		t.Errorf("network anomalies = %d, want 1", r.Summary.ByDimension[schema.DimNetwork])
	}
}

func TestPrivilegeEscalation_Process(t *testing.T) {
	b := baseWith("read")
	o := obsWith(b, "read")
	o.Process.PrivilegeChanges = []schema.PrivilegeChange{{FromUID: 1000, ToUID: 0, Syscall: "setuid"}}
	r := Analyze(b, o)

	if r.Verdict != schema.VerdictMalicious {
		t.Errorf("verdict = %s, want malicious (uid->0 is critical)", r.Verdict)
	}
	if r.Summary.BySeverity.Critical < 1 {
		t.Error("expected a critical anomaly for privilege escalation")
	}
}

func TestExecutableWritten_DropperFlaggedOnce(t *testing.T) {
	b := baseWith("read")
	o := obsWith(b, "read")
	// A dropped executable appears in both written and created (and is exec'd).
	payload := schema.FilePath{Path: "/tmp/payload", NormalizedPath: "/tmp/payload"}
	o.Filesystem.PathsWritten = []schema.FilePath{payload}
	o.Filesystem.PathsCreated = []schema.FilePath{payload}
	o.Filesystem.ExecsTouched = []schema.FilePath{payload}
	r := Analyze(b, o)

	var execWritten int
	for _, a := range r.Anomalies {
		if a.Type == schema.AnomalyExecutableWritten {
			execWritten++
		}
	}
	if execWritten != 1 {
		t.Errorf("executable_written anomalies = %d, want exactly 1 (deduped)", execWritten)
	}
	if r.Verdict != schema.VerdictMalicious {
		t.Errorf("verdict = %s, want malicious (dropped executable is critical)", r.Verdict)
	}
	if r.Summary.ByDimension[schema.DimFilesystem] != 1 {
		t.Errorf("filesystem anomalies = %d, want 1", r.Summary.ByDimension[schema.DimFilesystem])
	}
}

func TestRiskScore_IsCapped(t *testing.T) {
	b := baseWith()
	var names []string
	for i := 0; i < 20; i++ {
		names = append(names, fmt.Sprintf("unexpected_syscall_%d", i))
	}
	o := obsWith(b, names...) // 20 * weight 8 = 160, must cap at 100
	r := Analyze(b, o)

	if r.RiskScore != 100 {
		t.Errorf("risk score = %d, want capped at 100", r.RiskScore)
	}
	if r.Verdict != schema.VerdictMalicious {
		t.Errorf("verdict = %s, want malicious", r.Verdict)
	}
}

func TestContextMismatch_DowngradesConfidence(t *testing.T) {
	b := baseWith("read")
	b.Scrutiny.Quality.Confidence = schema.ConfidenceHigh
	o := obsWith(b, "read")
	o.Scrutiny.Platform.DetectedPlatform = schema.ContextWine // differs from baseline's native_linux
	r := Analyze(b, o)

	if r.ContextMatch {
		t.Error("expected context mismatch")
	}
	if r.Confidence != schema.ConfidenceMedium {
		t.Errorf("confidence = %s, want medium (downgraded from high)", r.Confidence)
	}
}

func TestWazuhAlert_LevelTracksVerdict(t *testing.T) {
	cases := []struct {
		name      string
		obs       []string
		wantLevel int
	}{
		{"clean", []string{"read"}, 3},
		{"malicious", []string{"read", "ptrace"}, 12},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := baseWith("read")
			o := obsWith(b, tc.obs...)
			r := Analyze(b, o)
			if r.WazuhAlert.RuleLevel != tc.wantLevel {
				t.Errorf("wazuh rule level = %d, want %d", r.WazuhAlert.RuleLevel, tc.wantLevel)
			}
		})
	}
}

func TestDeterministic_StableAnomalyOrder(t *testing.T) {
	b := baseWith("read")
	names := []string{"aaa", "zzz", "mmm", "bbb"}
	// Two independent analyses of the same inputs must produce identical
	// anomaly ordering despite Go's randomized map iteration.
	first := Analyze(b, obsWith(b, names...))
	for i := 0; i < 20; i++ {
		got := Analyze(b, obsWith(b, names...))
		if len(got.Anomalies) != len(first.Anomalies) {
			t.Fatalf("anomaly count varied: %d vs %d", len(got.Anomalies), len(first.Anomalies))
		}
		for j := range got.Anomalies {
			if got.Anomalies[j].Description != first.Anomalies[j].Description {
				t.Fatalf("anomaly order varied at %d: %q vs %q",
					j, got.Anomalies[j].Description, first.Anomalies[j].Description)
			}
		}
	}
}
