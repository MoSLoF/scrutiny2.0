// Scrutiny v2 — A babysitter for programs that haven't earned your trust.
//
// Cross-platform behavioral baseliner with eBPF/ETW sensing,
// Wine and WSL context awareness, and MITRE ATT&CK-mapped anomaly detection.
//
// Usage:
//
//	scrutiny baseline  --pid <pid> [--runs 3] [--duration 120] [--out baseline.json]
//	scrutiny observe   --pid <pid> --baseline baseline.json [--out observation.json]
//	scrutiny analyze   --baseline baseline.json --observation observation.json
//	scrutiny syscheck  (capability check only — no process required)
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/MoSLoF/scrutiny2.0/internal/analysis"
	"github.com/MoSLoF/scrutiny2.0/internal/context"
	"github.com/MoSLoF/scrutiny2.0/internal/schema"
	"github.com/MoSLoF/scrutiny2.0/internal/sensor"
	"github.com/MoSLoF/scrutiny2.0/internal/sensor/ebpf"
	"github.com/MoSLoF/scrutiny2.0/internal/sensor/network"
)

const banner = `
 ███████╗ ██████╗██████╗ ██╗   ██╗████████╗██╗███╗   ██╗██╗   ██╗
 ██╔════╝██╔════╝██╔══██╗██║   ██║╚══██╔══╝██║████╗  ██║╚██╗ ██╔╝
 ███████╗██║     ██████╔╝██║   ██║   ██║   ██║██╔██╗ ██║ ╚████╔╝ 
 ╚════██║██║     ██╔══██╗██║   ██║   ██║   ██║██║╚██╗██║  ╚██╔╝  
 ███████║╚██████╗██║  ██║╚██████╔╝   ██║   ██║██║ ╚████║   ██║   
 ╚══════╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝╚═╝  ╚═══╝   ╚═╝  
 v2.0.0 — MoSLoF/HoneyBadger Vanguard
 A babysitter for programs that haven't earned your trust.
`

type Config struct {
	Command     string
	PID         int
	Runs        int
	Duration    int
	BaselineOut string
	BaselineIn  string
	ObsOut      string
	ObsIn       string
	Verbose     bool
	JSONOutput  bool
}

func main() {
	cfg := parseArgs(os.Args[1:])

	if !cfg.JSONOutput {
		fmt.Print(banner)
	}

	switch cfg.Command {
	case "syscheck":
		runSyscheck(cfg)
	case "baseline":
		runBaseline(cfg)
	case "observe":
		runObserve(cfg)
	case "analyze":
		runAnalyze(cfg)
	default:
		printUsage()
		os.Exit(1)
	}
}

// ─── syscheck ────────────────────────────────────────────────────────────────

func runSyscheck(cfg Config) {
	fmt.Println("Running system capability check...")
	fmt.Println(strings.Repeat("─", 60))

	// Step 1: Detect execution context
	platformCtx, err := context.Detect()
	if err != nil {
		fatalf("Context detection failed: %v", err)
	}

	// Step 2: Probe sensor capabilities
	capReport := sensor.Probe(platformCtx)
	sensor.ApplyToContext(&platformCtx, capReport)

	if cfg.JSONOutput {
		printJSON(map[string]interface{}{
			"platform_context":  platformCtx,
			"capability_report": capReport,
		})
		return
	}

	// Human-readable output
	printContextTable(platformCtx)
	fmt.Println()
	printCapabilityTable(capReport)
	fmt.Println()
	printSensorCapabilityMatrix(platformCtx)

	// Exit code reflects sensor health
	if capReport.Backend == schema.BackendNone {
		fmt.Println("\n⚠  WARNING: No sensor backend available. Only network/filesystem polling possible.")
		os.Exit(2)
	}
	if capReport.ForcedFallback {
		fmt.Printf("\n⚠  INFO: eBPF unavailable — %s\n", capReport.FallbackReason)
	}

	fmt.Printf("\n✓  System check passed. Active backend: %s\n", capReport.Backend)
}

func printContextTable(ctx schema.PlatformContext) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "EXECUTION CONTEXT")
	fmt.Fprintln(w, "─────────────────")
	fmt.Fprintf(w, "  Platform:\t%s\n", ctx.DetectedPlatform)
	fmt.Fprintf(w, "  Host OS:\t%s\n", ctx.HostPlatform)
	fmt.Fprintf(w, "  OS Version:\t%s\n", ctx.OSVersion)
	fmt.Fprintf(w, "  Kernel:\t%s\n", ctx.KernelVersion)
	fmt.Fprintf(w, "  Interop Layer:\t%s\n", ctx.InteropLayer)
	if ctx.WineVersion != nil {
		fmt.Fprintf(w, "  Wine Version:\t%s\n", *ctx.WineVersion)
	}
	if ctx.WSLBuild != nil {
		fmt.Fprintf(w, "  WSL Build:\t%s\n", *ctx.WSLBuild)
	}
	if ctx.ContainerRuntime != nil {
		fmt.Fprintf(w, "  Container:\t%s\n", *ctx.ContainerRuntime)
	}
	w.Flush()
}

func printCapabilityTable(r sensor.CapabilityReport) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "SENSOR CAPABILITIES")
	fmt.Fprintln(w, "───────────────────")
	fmt.Fprintf(w, "  Active Backend:\t%s\n", r.Backend)
	fmt.Fprintf(w, "  Kernel Version:\t%d.%d.%d\n", r.KernelMajor, r.KernelMinor, r.KernelPatch)
	fmt.Fprintf(w, "  eBPF (>=4.15):\t%s\n", boolSymbol(r.EBPFPerfBuffer))
	fmt.Fprintf(w, "  eBPF Ring Buf (>=5.8):\t%s\n", boolSymbol(r.EBPFRingBuffer))
	fmt.Fprintf(w, "  CAP_BPF:\t%s\n", boolSymbol(r.HasCAP_BPF))
	fmt.Fprintf(w, "  CAP_SYS_PTRACE:\t%s\n", boolSymbol(r.HasCAP_SYS_PTRACE))
	fmt.Fprintf(w, "  strace:\t%s", boolSymbol(r.StraceAvailable))
	if r.StraceAvailable && r.StraceVersion != "" {
		fmt.Fprintf(w, " (%s)", r.StraceVersion)
	}
	fmt.Fprintln(w)
	if r.ForcedFallback {
		fmt.Fprintf(w, "  Fallback Reason:\t%s\n", r.FallbackReason)
	}
	w.Flush()

	if len(r.Warnings) > 0 {
		fmt.Println()
		for _, warn := range r.Warnings {
			fmt.Printf("  ⚠  %s\n", warn)
		}
	}
}

func printSensorCapabilityMatrix(ctx schema.PlatformContext) {
	c := ctx.Capabilities
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "SENSING DIMENSION AVAILABILITY")
	fmt.Fprintln(w, "──────────────────────────────")
	fmt.Fprintf(w, "  Syscalls:\t%s\n", c.Syscalls)
	fmt.Fprintf(w, "  Network:\t%s\n", c.Network)
	fmt.Fprintf(w, "  Filesystem:\t%s\n", c.Filesystem)
	fmt.Fprintf(w, "  Registry:\t%s\n", c.Registry)
	fmt.Fprintf(w, "  Memory:\t%s\n", c.Memory)
	fmt.Fprintf(w, "  Interop FS:\t%s\n", boolSymbol(c.InteropFS))
	w.Flush()
}

// ─── baseline ────────────────────────────────────────────────────────────────

func runBaseline(cfg Config) {
	if cfg.PID == 0 {
		fatalf("baseline requires --pid <n>")
	}

	platformCtx, capReport := detectAndProbe()
	fmt.Printf("Baselining PID %d — backend: %s, duration: %ds, runs: %d\n",
		cfg.PID, capReport.Backend, cfg.Duration, cfg.Runs)

	baseline := schema.NewBaseline(platformCtx, targetForPID(cfg.PID))
	baseline.Scrutiny.Quality.DurationSeconds = cfg.Duration

	syscalls, netObs := captureAll(cfg, capReport.Backend)
	if syscalls != nil {
		baseline.Syscalls = *syscalls
		baseline.Scrutiny.Quality.RunCount = 1
		baseline.Scrutiny.Quality.Confidence = schema.ConfidenceLow
	}
	if netObs != nil {
		baseline.Network = *netObs
	}

	if cfg.BaselineOut != "" {
		writeJSONFile(cfg.BaselineOut, baseline)
		fmt.Printf("Baseline written to %s\n", cfg.BaselineOut)
	} else if cfg.JSONOutput {
		printJSON(baseline)
	}
}

// ─── observe ─────────────────────────────────────────────────────────────────

func runObserve(cfg Config) {
	if cfg.PID == 0 {
		fatalf("observe requires --pid <n>")
	}
	if cfg.BaselineIn == "" {
		fatalf("observe requires --baseline <file> to link the observation to")
	}

	var baseline schema.Baseline
	if err := readJSONFile(cfg.BaselineIn, &baseline); err != nil {
		fatalf("reading baseline %s: %v", cfg.BaselineIn, err)
	}

	platformCtx, capReport := detectAndProbe()
	fmt.Printf("Observing PID %d against baseline %s — backend: %s, duration: %ds\n",
		cfg.PID, baseline.Scrutiny.BaselineID, capReport.Backend, cfg.Duration)

	obs := schema.NewObservation(baseline.Scrutiny.BaselineID, platformCtx, targetForPID(cfg.PID))
	obs.Scrutiny.Quality.DurationSeconds = cfg.Duration

	syscalls, netObs := captureAll(cfg, capReport.Backend)
	if syscalls != nil {
		obs.Syscalls = *syscalls
	}
	if netObs != nil {
		obs.Network = *netObs
	}

	obs.ContextMatch = baseline.Scrutiny.Platform.DetectedPlatform == platformCtx.DetectedPlatform
	if !obs.ContextMatch {
		fmt.Printf("⚠  context mismatch — baseline: %s, observed: %s (analysis confidence will be reduced)\n",
			baseline.Scrutiny.Platform.DetectedPlatform, platformCtx.DetectedPlatform)
	}

	if cfg.BaselineOut != "" {
		writeJSONFile(cfg.BaselineOut, obs)
		fmt.Printf("Observation written to %s\n", cfg.BaselineOut)
	} else if cfg.JSONOutput {
		printJSON(obs)
	}
}

// ─── analyze ─────────────────────────────────────────────────────────────────

func runAnalyze(cfg Config) {
	if cfg.BaselineIn == "" || cfg.ObsIn == "" {
		fatalf("analyze requires --baseline <file> and --observation <file>")
	}

	var baseline schema.Baseline
	if err := readJSONFile(cfg.BaselineIn, &baseline); err != nil {
		fatalf("reading baseline %s: %v", cfg.BaselineIn, err)
	}
	var obs schema.Observation
	if err := readJSONFile(cfg.ObsIn, &obs); err != nil {
		fatalf("reading observation %s: %v", cfg.ObsIn, err)
	}

	result := analysis.Analyze(&baseline, &obs)

	if cfg.BaselineOut != "" {
		writeJSONFile(cfg.BaselineOut, result)
	}
	if cfg.JSONOutput {
		printJSON(result)
		return
	}
	printAnalysis(result)
	if cfg.BaselineOut != "" {
		fmt.Printf("\nAnalysis written to %s\n", cfg.BaselineOut)
	}
}

// ─── Shared capture helpers ────────────────────────────────────────────────────

// detectAndProbe runs context detection + capability probing and stamps the
// probe results back into the platform context.
func detectAndProbe() (schema.PlatformContext, sensor.CapabilityReport) {
	platformCtx, err := context.Detect()
	if err != nil {
		fatalf("context detection failed: %v", err)
	}
	capReport := sensor.Probe(platformCtx)
	sensor.ApplyToContext(&platformCtx, capReport)
	return platformCtx, capReport
}

// targetForPID reads what it can about the target process from /proc.
func targetForPID(pid int) schema.TargetProcess {
	target := schema.TargetProcess{UID: os.Getuid()}
	if comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid)); err == nil {
		target.Name = strings.TrimSpace(string(comm))
	}
	if exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)); err == nil {
		target.Path = exe
	}
	return target
}

// captureAll runs the syscall and network collectors against the target over
// the same window, concurrently, and returns both observations (either may be
// nil). Network polling runs in the background while the syscall backend holds
// the foreground for the capture duration.
func captureAll(cfg Config, backend schema.SensorBackend) (*schema.SyscallsObservation, *schema.NetworkObservation) {
	dur := time.Duration(cfg.Duration) * time.Second

	var netObs *schema.NetworkObservation
	done := make(chan struct{})
	go func() {
		defer close(done)
		no, err := network.Collect(cfg.PID, dur)
		if err != nil {
			fmt.Printf("network collection failed: %v\n", err)
			return
		}
		netObs = no
	}()

	syscalls := captureSyscalls(cfg, backend)
	<-done

	if netObs != nil {
		fmt.Printf("Captured %d listening port(s), %d outbound connection(s)\n",
			len(netObs.ListeningPorts), len(netObs.OutboundConnections))
	}
	return syscalls, netObs
}

// captureSyscalls runs the active backend against the target for the configured
// duration. Returns nil when no syscall backend is available (or is stubbed),
// leaving the caller's record with metadata only.
func captureSyscalls(cfg Config, backend schema.SensorBackend) *schema.SyscallsObservation {
	switch backend {
	case schema.BackendEBPF:
		so, err := ebpf.Collect(uint32(cfg.PID), time.Duration(cfg.Duration)*time.Second)
		if err != nil {
			fatalf("eBPF collection failed: %v", err)
		}
		fmt.Printf("Captured %d distinct syscalls via eBPF\n", len(so.Observed))
		return so
	case schema.BackendStrace:
		fmt.Println("strace backend selected — collector wiring pending (Phase 2b)")
	default:
		fmt.Println("No syscall backend available — capturing metadata only")
	}
	return nil
}

// printAnalysis renders an AnalysisResult as a human-readable report.
func printAnalysis(r *schema.AnalysisResult) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ANALYSIS RESULT")
	fmt.Fprintln(w, "───────────────")
	fmt.Fprintf(w, "  Verdict:\t%s\n", strings.ToUpper(string(r.Verdict)))
	fmt.Fprintf(w, "  Risk Score:\t%d / 100\n", r.RiskScore)
	fmt.Fprintf(w, "  Confidence:\t%s\n", r.Confidence)
	fmt.Fprintf(w, "  Context Match:\t%s\n", boolSymbol(r.ContextMatch))
	fmt.Fprintf(w, "  Anomalies:\t%d  (critical %d, high %d, medium %d, low %d, info %d)\n",
		r.Summary.TotalAnomalies,
		r.Summary.BySeverity.Critical, r.Summary.BySeverity.High,
		r.Summary.BySeverity.Medium, r.Summary.BySeverity.Low, r.Summary.BySeverity.Info)
	w.Flush()

	if len(r.Anomalies) == 0 {
		fmt.Println("\n  No deviations from baseline.")
		return
	}

	fmt.Println()
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  SEVERITY\tDIMENSION\tMITRE\tDESCRIPTION")
	fmt.Fprintln(tw, "  ────────\t─────────\t─────\t───────────")
	for _, a := range r.Anomalies {
		sev := strings.ToUpper(string(a.Severity))
		if a.Suppressed {
			sev = "suppressed"
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n", sev, a.Dimension, a.MITRETechnique, a.Description)
	}
	tw.Flush()
}

// ─── CLI Parsing ─────────────────────────────────────────────────────────────

func parseArgs(args []string) Config {
	cfg := Config{
		Runs:     3,
		Duration: 120,
	}

	if len(args) == 0 {
		printUsage()
		os.Exit(1)
	}

	cfg.Command = args[0]
	args = args[1:]

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--pid":
			if i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%d", &cfg.PID)
				i++
			}
		case "--runs":
			if i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%d", &cfg.Runs)
				i++
			}
		case "--duration":
			if i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%d", &cfg.Duration)
				i++
			}
		case "--out":
			if i+1 < len(args) {
				cfg.BaselineOut = args[i+1]
				i++
			}
		case "--baseline":
			if i+1 < len(args) {
				cfg.BaselineIn = args[i+1]
				i++
			}
		case "--observation":
			if i+1 < len(args) {
				cfg.ObsIn = args[i+1]
				i++
			}
		case "--verbose", "-v":
			cfg.Verbose = true
		case "--json":
			cfg.JSONOutput = true
		}
	}

	return cfg
}

func printUsage() {
	fmt.Print(banner)
	fmt.Print(`USAGE:
  scrutiny <command> [options]

COMMANDS:
  syscheck              Check sensor capabilities (no target required)
  baseline  --pid <n>   Capture behavioral baseline for a process
  observe   --pid <n> --baseline <file>
                        Capture observation for comparison
  analyze   --baseline <file> --observation <file>
                        Compare and score behavioral deviation

OPTIONS:
  --pid <n>             Target process PID
  --runs <n>            Number of baseline runs (default: 3)
  --duration <s>        Seconds per run (default: 120)
  --out <file>          Output file path
  --baseline <file>     Baseline JSON file for observe/analyze
  --observation <file>  Observation JSON file for analyze
  --verbose, -v         Verbose output
  --json                Machine-readable JSON output

EXAMPLES:
  scrutiny syscheck
  scrutiny baseline --pid 1234 --runs 3 --out ./baselines/firefox.json
  scrutiny observe  --pid 5678 --baseline ./baselines/firefox.json
  scrutiny analyze  --baseline ./baselines/firefox.json --observation ./obs.json
`)
}

// ─── Utilities ───────────────────────────────────────────────────────────────

func boolSymbol(b bool) string {
	if b {
		return "✓"
	}
	return "✗"
}

func printJSON(v interface{}) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fatalf("JSON encode error: %v", err)
	}
}

func readJSONFile(path string, v interface{}) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewDecoder(f).Decode(v)
}

func writeJSONFile(path string, v interface{}) {
	f, err := os.Create(path)
	if err != nil {
		fatalf("creating output file %s: %v", path, err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fatalf("writing JSON to %s: %v", path, err)
	}
}

func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "ERROR: "+format+"\n", args...)
	os.Exit(1)
}
