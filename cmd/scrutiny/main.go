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

	"github.com/MoSLoF/scrutiny/internal/context"
	"github.com/MoSLoF/scrutiny/internal/schema"
	"github.com/MoSLoF/scrutiny/internal/sensor"
	"github.com/MoSLoF/scrutiny/internal/sensor/ebpf"
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

// ─── Subcommand stubs ────────────────────────────────────────────────────────

func runBaseline(cfg Config) {
	if cfg.PID == 0 {
		fatalf("baseline requires --pid <n>")
	}

	platformCtx, err := context.Detect()
	if err != nil {
		fatalf("context detection failed: %v", err)
	}
	capReport := sensor.Probe(platformCtx)
	sensor.ApplyToContext(&platformCtx, capReport)

	fmt.Printf("Baselining PID %d — backend: %s, duration: %ds, runs: %d\n",
		cfg.PID, capReport.Backend, cfg.Duration, cfg.Runs)

	target := schema.TargetProcess{UID: os.Getuid()}
	if comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", cfg.PID)); err == nil {
		target.Name = strings.TrimSpace(string(comm))
	}
	if exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", cfg.PID)); err == nil {
		target.Path = exe
	}

	baseline := schema.NewBaseline(platformCtx, target)
	baseline.Scrutiny.Quality.DurationSeconds = cfg.Duration

	switch capReport.Backend {
	case schema.BackendEBPF:
		obs, err := ebpf.Collect(uint32(cfg.PID), time.Duration(cfg.Duration)*time.Second)
		if err != nil {
			fatalf("eBPF collection failed: %v", err)
		}
		baseline.Syscalls = *obs
		baseline.Scrutiny.Quality.RunCount = 1
		baseline.Scrutiny.Quality.Confidence = schema.ConfidenceLow
		fmt.Printf("Captured %d distinct syscalls via eBPF\n", len(obs.Observed))
	case schema.BackendStrace:
		fmt.Println("strace backend selected — collector wiring pending (Phase 2b)")
	default:
		fmt.Println("No syscall backend available — baseline will cover network/filesystem only (Phase 2b)")
	}

	if cfg.BaselineOut != "" {
		writeJSONFile(cfg.BaselineOut, baseline)
		fmt.Printf("Baseline written to %s\n", cfg.BaselineOut)
	} else if cfg.JSONOutput {
		printJSON(baseline)
	}
}

func runObserve(cfg Config) {
	fmt.Print("Observe mode — full wiring lands with the analysis engine (Phase 3)\n")
}

func runAnalyze(cfg Config) {
	fmt.Print("Analyze mode — analysis engine in Phase 3\n")
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
