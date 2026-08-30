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

// TestSleepwalkerShape reproduces the exact network fingerprint from the
// SLEEPWALKER writeup: a raw AF_PACKET socket bound to every interface
// (ETH_P_ALL), and NOTHING in listening ports or outbound connections —
// zero C2, zero bind, zero connect. Before the raw/packet-socket patch,
// this observation would score 0 and verdict clean, because diffNetwork
// only ever looked at ListeningPorts and OutboundConnections.
func TestSleepwalkerShape_RawPacketSocketAloneIsFlagged(t *testing.T) {
	b := baseWith("read")
	o := obsWith(b, "read")
	o.Network.RawSockets = []schema.RawSocket{
		{Family: "packet", Protocol: "0x0003", Interface: "*"},
	}
	r := Analyze(b, o)

	if r.Verdict == schema.VerdictClean {
		t.Error("a bare raw-promiscuous listener with no ports/connections must not score clean")
	}
	var found bool
	for _, a := range r.Anomalies {
		if a.Type == schema.AnomalyRawSocketOpened {
			found = true
		}
	}
	if !found {
		t.Error("expected a raw_socket_opened anomaly")
	}
}

// TestPromiscuousMode_OnlyFlaggedAlongsidePacketSocket confirms the
// deliberate false-positive guard: promiscuous mode is system-wide kernel
// state (not attributable to one process), so it should NOT be flagged as
// an anomaly on its own — only when the SAME observed process also holds a
// packet-family socket, tying the two together.
func TestPromiscuousMode_OnlyFlaggedAlongsidePacketSocket(t *testing.T) {
	b := baseWith("read")

	// Promiscuous interface present, but this process holds no packet
	// socket — e.g. some unrelated tool (tcpdump) set it. Must NOT flag.
	oNoPacket := obsWith(b, "read")
	oNoPacket.Network.PromiscuousInterfaces = []string{"eth0"}
	rNoPacket := Analyze(b, oNoPacket)
	for _, a := range rNoPacket.Anomalies {
		if a.Type == schema.AnomalyPromiscuousModeObserved {
			t.Error("promiscuous mode should not be flagged without a packet socket on this process")
		}
	}

	// Same promiscuous interface, but this process ALSO holds a packet
	// socket — now it's a meaningful compound signal. Must flag.
	oWithPacket := obsWith(b, "read")
	oWithPacket.Network.PromiscuousInterfaces = []string{"eth0"}
	oWithPacket.Network.RawSockets = []schema.RawSocket{{Family: "packet", Protocol: "0x0003", Interface: "*"}}
	rWithPacket := Analyze(b, oWithPacket)
	var found bool
	for _, a := range rWithPacket.Anomalies {
		if a.Type == schema.AnomalyPromiscuousModeObserved {
			found = true
		}
	}
	if !found {
		t.Error("expected promiscuous_mode_observed anomaly when process also holds a packet socket")
	}
}

func TestNewChildProcess_DedupedByPath(t *testing.T) {
	b := baseWith("read")
	o := obsWith(b, "read")
	// Same helper spawned three times (distinct instances, same path).
	sleepChild := schema.ChildProcess{Name: "sleep", Path: "/usr/bin/sleep", UID: 1000}
	o.Process.ChildrenSpawned = []schema.ChildProcess{sleepChild, sleepChild, sleepChild}
	r := Analyze(b, o)

	var newChild int
	for _, a := range r.Anomalies {
		if a.Type == schema.AnomalyNewChildProcess {
			newChild++
		}
	}
	if newChild != 1 {
		t.Errorf("new_child_process anomalies = %d, want 1 (deduped by path)", newChild)
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

func TestSleepwalker_RegistryDefenseImpairmentFlagged(t *testing.T) {
	// Baseline: a clean ERAAgent with no registry weakening.
	b := baseWith()
	b.Scrutiny.Platform.DetectedPlatform = schema.ContextNativeWindows
	// Observation: the two SLEEPWALKER weakening keys were written.
	o := schema.NewObservation(b.Scrutiny.BaselineID, b.Scrutiny.Platform, schema.TargetProcess{Name: "ERAAgent.exe"})
	o.Registry = schema.RegistryObservation{
		Available:        true,
		SecurityWeakened: true,
		KeysWritten: []schema.RegistryKey{
			{Key: `HKLM\...\Lsa\EveryoneIncludesAnonymous`, Sensitive: true},
			{Key: `HKLM\...\LanmanServer\Parameters\NullSessionPipes`, Sensitive: true},
		},
	}
	r := Analyze(b, o)

	var impair int
	for _, a := range r.Anomalies {
		if a.Type == schema.AnomalyRegistryDefenseImpair {
			impair++
			if a.MITRETechnique != "T1562" {
				t.Errorf("defense-impair MITRE = %s, want T1562", a.MITRETechnique)
			}
		}
		if a.Type == schema.AnomalyRegistryNewWrite {
			t.Error("sensitive weakening keys should not also fire a generic new-write anomaly")
		}
	}
	if impair != 1 {
		t.Errorf("defense-impairment anomalies = %d, want 1", impair)
	}
	if r.Verdict == schema.VerdictClean {
		t.Error("SLEEPWALKER registry weakening should not read as clean")
	}
}

func TestRegistry_NewWriteFlaggedOncePerKey(t *testing.T) {
	b := baseWith()
	o := obsWith(b)
	o.Registry.KeysWritten = []schema.RegistryKey{
		{Key: `HKCU\Software\App\New`}, {Key: `HKCU\Software\App\New`}, // same key twice
	}
	r := Analyze(b, o)
	var n int
	for _, a := range r.Anomalies {
		if a.Type == schema.AnomalyRegistryNewWrite {
			n++
		}
	}
	if n != 1 {
		t.Errorf("new_write anomalies = %d, want 1 (deduped by key)", n)
	}
}

func TestSleepwalker_SideLoadedModuleFlagged(t *testing.T) {
	b := baseWith()
	b.Memory.MappedFiles = []string{`C:\Windows\System32\kernel32.dll`}
	o := obsWith(b)
	o.Memory.MappedFiles = []string{
		`C:\Windows\System32\kernel32.dll`,          // in baseline
		`C:\Program Files\ESET\...\Agent\dpapi.dll`, // NEW — side-loaded
	}
	r := Analyze(b, o)

	var module int
	for _, a := range r.Anomalies {
		if a.Type == schema.AnomalyUnexpectedModuleLoad {
			module++
			if a.MITRETechnique != "T1574" {
				t.Errorf("module-load MITRE = %s, want T1574", a.MITRETechnique)
			}
		}
	}
	if module != 1 {
		t.Errorf("unexpected-module-load anomalies = %d, want 1 (only the new dpapi.dll)", module)
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
