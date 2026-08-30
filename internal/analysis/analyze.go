// Package analysis implements Scrutiny's behavioral deviation engine: it
// compares an observation against the baseline it was captured against,
// emits per-dimension anomalies, weights and MITRE-maps them, applies noise
// suppression, and rolls the result up into a risk score, verdict, and a
// pre-formatted Wazuh alert.
//
// The engine is pure and deterministic: given the same baseline and
// observation it produces the same anomalies in the same order (only the
// generated IDs and AnalyzedAt timestamp vary). That makes it unit-testable
// without any sensor, kernel, or platform involvement.
package analysis

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/MoSLoF/scrutiny2.0/internal/schema"
)

// Analyze compares obs against baseline and returns a full AnalysisResult.
func Analyze(baseline *schema.Baseline, obs *schema.Observation) *schema.AnalysisResult {
	cfg := effectiveConfig(baseline.AnomalyCfg)

	var anomalies []schema.Anomaly
	anomalies = append(anomalies, diffSyscalls(baseline, obs, cfg)...)
	anomalies = append(anomalies, diffNetwork(baseline, obs, cfg)...)
	anomalies = append(anomalies, diffFilesystem(baseline, obs, cfg)...)
	anomalies = append(anomalies, diffRegistry(baseline, obs, cfg)...)
	anomalies = append(anomalies, diffProcess(baseline, obs, cfg)...)
	anomalies = append(anomalies, diffMemory(baseline, obs, cfg)...)

	sortAnomalies(anomalies)

	ctxMatch := baseline.Scrutiny.Platform.DetectedPlatform == obs.Scrutiny.Platform.DetectedPlatform
	score := riskScore(anomalies)
	verdict := verdictFor(score, anomalies)
	summary := summarize(anomalies)

	// A context mismatch (e.g. baseline captured on native Linux, observed
	// under Wine) makes any comparison less trustworthy — never report high
	// confidence across that boundary.
	confidence := baseline.Scrutiny.Quality.Confidence
	if !ctxMatch && confidence == schema.ConfidenceHigh {
		confidence = schema.ConfidenceMedium
	}

	return &schema.AnalysisResult{
		AnalysisID:    uuid.New().String(),
		BaselineID:    baseline.Scrutiny.BaselineID,
		ObservationID: obs.ObservationID,
		AnalyzedAt:    time.Now().UTC(),
		RiskScore:     score,
		Verdict:       verdict,
		Confidence:    confidence,
		ContextMatch:  ctxMatch,
		Anomalies:     anomalies,
		Summary:       summary,
		WazuhAlert:    wazuhAlert(verdict, score, summary),
	}
}

// ─── Per-dimension diffs ───────────────────────────────────────────────────────

func diffSyscalls(b *schema.Baseline, o *schema.Observation, cfg schema.AnomalyConfig) []schema.Anomaly {
	suspicious := stringSet(b.Syscalls.SuspiciousNeverExpected)
	benign := stringSet(cfg.SuppressNoise.HighFrequencyBenignSyscalls)

	var out []schema.Anomaly
	for name, rec := range o.Syscalls.Observed {
		if _, expected := b.Syscalls.Observed[name]; expected {
			continue
		}
		a := newAnomaly(cfg, schema.DimSyscalls, schema.AnomalyUnexpectedSyscall,
			fmt.Sprintf("syscall %q not present in baseline", name),
			nil, name, rec.FirstSeenOffsetMS)

		// An always-suspicious syscall (ptrace, module loading, ...) is never
		// just "unexpected" — force it to critical regardless of the weight.
		if suspicious[name] {
			a.Severity = schema.SeverityCritical
			a.Description = fmt.Sprintf("suspicious syscall %q (never expected) appeared", name)
		} else if benign[name] {
			// High-frequency benign syscall — surface it but don't score it.
			suppress(&a, "high-frequency benign syscall (noise-suppressed)")
		}
		out = append(out, a)
	}
	return out
}

func diffNetwork(b *schema.Baseline, o *schema.Observation, cfg schema.AnomalyConfig) []schema.Anomaly {
	var out []schema.Anomaly

	basePorts := map[string]bool{}
	for _, p := range b.Network.ListeningPorts {
		basePorts[portKey(p)] = true
	}
	for _, p := range o.Network.ListeningPorts {
		if basePorts[portKey(p)] {
			continue
		}
		out = append(out, newAnomaly(cfg, schema.DimNetwork, schema.AnomalyNewListeningPort,
			fmt.Sprintf("new listening port %s/%d on %s", p.Proto, p.Port, p.Address),
			nil, p, p.FirstSeenOffsetMS))
	}

	baseConns := map[string]bool{}
	for _, c := range b.Network.OutboundConnections {
		baseConns[connKey(c)] = true
	}
	for _, c := range o.Network.OutboundConnections {
		if baseConns[connKey(c)] {
			continue
		}
		dst := c.DestinationIP
		if c.DNSName != "" {
			dst = c.DNSName
		}
		out = append(out, newAnomaly(cfg, schema.DimNetwork, schema.AnomalyNewOutboundConnection,
			fmt.Sprintf("new outbound connection to %s:%d (%s)", dst, c.DestinationPort, c.Proto),
			nil, c, c.FirstSeenOffsetMS))
	}

	// Raw and packet-family sockets never show up in the listening-port or
	// outbound-connection diffs above — a SLEEPWALKER-style listener (raw
	// AF_PACKET, promiscuous, no bind, no connect) is invisible to both.
	baseRaw := map[string]bool{}
	for _, r := range b.Network.RawSockets {
		baseRaw[rawKey(r)] = true
	}
	hasPacketSocket := false
	for _, r := range o.Network.RawSockets {
		if r.Family == "packet" {
			hasPacketSocket = true
		}
		if baseRaw[rawKey(r)] {
			continue
		}
		desc := fmt.Sprintf("new raw socket: family %s, protocol %s", r.Family, r.Protocol)
		if r.Family == "packet" {
			desc = fmt.Sprintf("new packet-capture socket: protocol %s on interface %s", r.Protocol, r.Interface)
		}
		out = append(out, newAnomaly(cfg, schema.DimNetwork, schema.AnomalyRawSocketOpened,
			desc, nil, r, r.FirstSeenOffsetMS))
	}

	// PromiscuousInterfaces is system-wide state, not attributable to this
	// process by itself — another process or a legitimate capture tool could
	// be the cause. Only surface it as an anomaly when THIS process also
	// holds a packet-family socket; otherwise it's most likely unrelated and
	// would be pure noise on any box that runs tcpdump/Wireshark/another
	// security agent.
	if hasPacketSocket {
		newPromisc := diffStrings(b.Network.PromiscuousInterfaces, o.Network.PromiscuousInterfaces)
		if len(newPromisc) > 0 {
			out = append(out, newAnomaly(cfg, schema.DimNetwork, schema.AnomalyPromiscuousModeObserved,
				fmt.Sprintf("interface(s) newly in promiscuous mode while process holds a packet socket: %s",
					strings.Join(newPromisc, ", ")),
				b.Network.PromiscuousInterfaces, o.Network.PromiscuousInterfaces, 0))
		}
	}

	return out
}

func diffFilesystem(b *schema.Baseline, o *schema.Observation, cfg schema.AnomalyConfig) []schema.Anomaly {
	var out []schema.Anomaly

	// Executables newly written or created that the baseline never touched.
	// A path can appear in both PathsWritten and PathsCreated — flag it once.
	baseExec := map[string]bool{}
	for _, f := range b.Filesystem.ExecsTouched {
		baseExec[f.NormalizedPath] = true
	}
	flagged := map[string]bool{}
	for _, f := range append(append([]schema.FilePath{}, o.Filesystem.PathsWritten...), o.Filesystem.PathsCreated...) {
		if !isExecutable(o, f) || baseExec[f.NormalizedPath] || flagged[f.NormalizedPath] {
			continue
		}
		flagged[f.NormalizedPath] = true
		out = append(out, newAnomaly(cfg, schema.DimFilesystem, schema.AnomalyExecutableWritten,
			fmt.Sprintf("executable written to %s", f.Path), nil, f.Path, 0))
	}

	// Writes that cross the WSL/Wine interop boundary — suppressed for
	// well-known system paths that legitimately get touched.
	interopNoise := stringSet(cfg.SuppressNoise.KnownInteropPaths)
	for _, f := range o.Filesystem.PathsWritten {
		if !f.InteropPath {
			continue
		}
		a := newAnomaly(cfg, schema.DimFilesystem, schema.AnomalyWSLInteropFSWrite,
			fmt.Sprintf("write across interop boundary: %s", f.Path), nil, f.Path, 0)
		if hasPrefixAny(f.Path, interopNoise) {
			suppress(&a, "known interop system path (noise-suppressed)")
		}
		out = append(out, a)
	}
	return out
}

func diffRegistry(b *schema.Baseline, o *schema.Observation, cfg schema.AnomalyConfig) []schema.Anomaly {
	var out []schema.Anomaly
	if o.Registry.PersistencePathTouched && !b.Registry.PersistencePathTouched {
		out = append(out, newAnomaly(cfg, schema.DimRegistry, schema.AnomalyRegistryPersistence,
			"registry persistence path written", b.Registry.PersistencePathTouched, true, 0))
	}
	return out
}

func diffProcess(b *schema.Baseline, o *schema.Observation, cfg schema.AnomalyConfig) []schema.Anomaly {
	var out []schema.Anomaly

	baseChildren := map[string]string{} // path -> sha256
	for _, c := range b.Process.ChildrenSpawned {
		baseChildren[c.Path] = c.SHA256
	}
	// A process that spawns the same helper repeatedly (e.g. sleep in a loop)
	// is one finding per distinct binary, not one per invocation — flag each
	// child path once.
	flagged := map[string]bool{}
	for _, c := range o.Process.ChildrenSpawned {
		if flagged[c.Path] {
			continue
		}
		baseHash, known := baseChildren[c.Path]
		switch {
		case !known:
			flagged[c.Path] = true
			out = append(out, newAnomaly(cfg, schema.DimProcess, schema.AnomalyNewChildProcess,
				fmt.Sprintf("new child process %s (%s)", c.Name, c.Path), nil, c, c.FirstSeenOffsetMS))
		case baseHash != "" && c.SHA256 != "" && baseHash != c.SHA256:
			flagged[c.Path] = true
			out = append(out, newAnomaly(cfg, schema.DimProcess, schema.AnomalyChildExecMismatch,
				fmt.Sprintf("child %s hash differs from baseline", c.Path), baseHash, c.SHA256, c.FirstSeenOffsetMS))
		}
	}

	for _, pc := range o.Process.PrivilegeChanges {
		if pc.ToUID == 0 || pc.ToUID < pc.FromUID {
			out = append(out, newAnomaly(cfg, schema.DimProcess, schema.AnomalyPrivilegeEscalation,
				fmt.Sprintf("privilege change uid %d -> %d via %s", pc.FromUID, pc.ToUID, pc.Syscall),
				pc.FromUID, pc.ToUID, pc.OffsetMS))
		}
	}

	if len(o.Process.ProcFSReads) > len(b.Process.ProcFSReads) {
		out = append(out, newAnomaly(cfg, schema.DimProcess, schema.AnomalyProcFSReadOtherPID,
			"reads of other processes' /proc entries", len(b.Process.ProcFSReads), len(o.Process.ProcFSReads), 0))
	}
	return out
}

func diffMemory(b *schema.Baseline, o *schema.Observation, cfg schema.AnomalyConfig) []schema.Anomaly {
	var out []schema.Anomaly
	for _, r := range o.Memory.ExecutableRegions {
		if r.Suspicious && r.BackedBy == "anonymous" {
			out = append(out, newAnomaly(cfg, schema.DimMemory, schema.AnomalyExecMemoryAnonymous,
				fmt.Sprintf("executable anonymous memory region %s", r.AddressRange), nil, r.AddressRange, 0))
		}
	}
	return out
}

// ─── Scoring & rollup ──────────────────────────────────────────────────────────

// riskScore is the capped sum of non-suppressed anomaly weights (0..100).
func riskScore(anomalies []schema.Anomaly) int {
	sum := 0
	for _, a := range anomalies {
		if a.Suppressed {
			continue
		}
		sum += a.Weight
	}
	if sum > 100 {
		sum = 100
	}
	return sum
}

// verdictFor combines the aggregate score with the presence of high-severity
// findings — a single critical anomaly is malicious even at a low total score.
func verdictFor(score int, anomalies []schema.Anomaly) schema.Verdict {
	var crit, high int
	for _, a := range anomalies {
		if a.Suppressed {
			continue
		}
		switch a.Severity {
		case schema.SeverityCritical:
			crit++
		case schema.SeverityHigh:
			high++
		}
	}
	switch {
	case crit > 0 || score >= 60:
		return schema.VerdictMalicious
	case high > 0 || score >= 20:
		return schema.VerdictSuspicious
	default:
		return schema.VerdictClean
	}
}

func summarize(anomalies []schema.Anomaly) schema.AnalysisSummary {
	s := schema.AnalysisSummary{
		ByDimension:      map[schema.Dimension]int{},
		ByMITRETechnique: map[string]int{},
	}
	for _, a := range anomalies {
		if a.Suppressed {
			continue
		}
		s.TotalAnomalies++
		switch a.Severity {
		case schema.SeverityCritical:
			s.BySeverity.Critical++
		case schema.SeverityHigh:
			s.BySeverity.High++
		case schema.SeverityMedium:
			s.BySeverity.Medium++
		case schema.SeverityLow:
			s.BySeverity.Low++
		case schema.SeverityInfo:
			s.BySeverity.Info++
		}
		s.ByDimension[a.Dimension]++
		if a.MITRETechnique != "" {
			s.ByMITRETechnique[a.MITRETechnique]++
		}
	}
	return s
}

func wazuhAlert(v schema.Verdict, score int, s schema.AnalysisSummary) schema.WazuhAlert {
	level, ruleID := 3, 100010
	switch v {
	case schema.VerdictSuspicious:
		level, ruleID = 8, 100020
	case schema.VerdictMalicious:
		level, ruleID = 12, 100030
	}
	return schema.WazuhAlert{
		RuleID:          ruleID,
		RuleLevel:       level,
		RuleDescription: fmt.Sprintf("Scrutiny: %s behavior (risk %d, %d anomalies)", v, score, s.TotalAnomalies),
		Data:            s,
	}
}

// ─── Helpers ───────────────────────────────────────────────────────────────────

func effectiveConfig(c schema.AnomalyConfig) schema.AnomalyConfig {
	if c.Weights == nil {
		c.Weights = schema.DefaultAnomalyWeights
	}
	if c.MITREMappings == nil {
		c.MITREMappings = schema.DefaultMITREMappings
	}
	if c.SuppressNoise.HighFrequencyBenignSyscalls == nil && c.SuppressNoise.KnownInteropPaths == nil {
		c.SuppressNoise = schema.DefaultNoiseSuppress
	}
	return c
}

func newAnomaly(cfg schema.AnomalyConfig, dim schema.Dimension, t schema.AnomalyType,
	desc string, baseVal, obsVal interface{}, offset int64) schema.Anomaly {
	w := cfg.Weights[t]
	return schema.Anomaly{
		AnomalyID:         uuid.New().String(),
		Dimension:         dim,
		Type:              t,
		Severity:          severityFromWeight(w),
		Weight:            w,
		MITRETechnique:    cfg.MITREMappings[t],
		Description:       desc,
		BaselineValue:     baseVal,
		ObservedValue:     obsVal,
		FirstSeenOffsetMS: offset,
	}
}

func severityFromWeight(w int) schema.Severity {
	switch {
	case w >= 10:
		return schema.SeverityCritical
	case w >= 8:
		return schema.SeverityHigh
	case w >= 5:
		return schema.SeverityMedium
	case w >= 2:
		return schema.SeverityLow
	default:
		return schema.SeverityInfo
	}
}

func suppress(a *schema.Anomaly, reason string) {
	a.Suppressed = true
	a.SuppressionReason = &reason
}

// sortAnomalies orders anomalies deterministically: active before suppressed,
// then by descending weight, then dimension, then description — so reports and
// tests see a stable, severity-first ordering regardless of map iteration.
func sortAnomalies(a []schema.Anomaly) {
	sort.SliceStable(a, func(i, j int) bool {
		if a[i].Suppressed != a[j].Suppressed {
			return !a[i].Suppressed
		}
		if a[i].Weight != a[j].Weight {
			return a[i].Weight > a[j].Weight
		}
		if a[i].Dimension != a[j].Dimension {
			return a[i].Dimension < a[j].Dimension
		}
		return a[i].Description < a[j].Description
	})
}

func stringSet(items []string) map[string]bool {
	s := make(map[string]bool, len(items))
	for _, it := range items {
		s[it] = true
	}
	return s
}

func portKey(p schema.ListeningPort) string {
	return fmt.Sprintf("%s|%s|%d", p.Proto, p.Address, p.Port)
}

func connKey(c schema.OutboundConnection) string {
	return fmt.Sprintf("%s|%s|%d", c.Proto, c.DestinationIP, c.DestinationPort)
}

func rawKey(r schema.RawSocket) string {
	return fmt.Sprintf("%s|%s|%s", r.Family, r.Protocol, r.Interface)
}

// diffStrings returns the entries of newList absent from oldList.
func diffStrings(oldList, newList []string) []string {
	old := stringSet(oldList)
	var out []string
	for _, s := range newList {
		if !old[s] {
			out = append(out, s)
		}
	}
	return out
}

func isExecutable(o *schema.Observation, f schema.FilePath) bool {
	for _, e := range o.Filesystem.ExecsTouched {
		if e.NormalizedPath == f.NormalizedPath || e.Path == f.Path {
			return true
		}
	}
	return false
}

func hasPrefixAny(path string, prefixes map[string]bool) bool {
	for p := range prefixes {
		if len(p) > 0 && len(path) >= len(p) && path[:len(p)] == p {
			return true
		}
	}
	return false
}
