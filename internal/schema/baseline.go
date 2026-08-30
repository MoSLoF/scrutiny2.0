// Package schema defines the canonical data structures for Scrutiny v2.
// All sensor modules, storage backends, and analysis engines operate on
// these types. The JSON tags are the wire format — never change a tag
// without bumping SchemaVersion.
package schema

import (
	"time"

	"github.com/google/uuid"
)

const (
	// SchemaVersion 2.1.0 added exit-side syscall data (ExitCount, ErrorCount,
	// RetSample, latency) to SyscallRecord.
	SchemaVersion = "2.1.0"
	ToolVersion   = "2.0.0"
)

// ─── Execution Context ───────────────────────────────────────────────────────

// ExecutionContext identifies the runtime environment in which a process
// is observed. This is a first-class field on every record — not metadata.
type ExecutionContext string

const (
	ContextNativeLinux   ExecutionContext = "native_linux"
	ContextWSL1          ExecutionContext = "wsl1"
	ContextWSL2          ExecutionContext = "wsl2"
	ContextWine          ExecutionContext = "wine"
	ContextNativeWindows ExecutionContext = "native_windows"
	ContextContainer     ExecutionContext = "container"
	ContextUnknown       ExecutionContext = "unknown"
)

// SensorAvailability describes what a sensor can see in a given context.
type SensorAvailability string

const (
	SensorFull        SensorAvailability = "full"
	SensorPartial     SensorAvailability = "partial"
	SensorForwarded   SensorAvailability = "forwarded" // WSL2 network
	SensorShared      SensorAvailability = "shared"    // WSL1 network
	SensorNamespaced  SensorAvailability = "namespaced"
	SensorInterop     SensorAvailability = "interop"
	SensorEmulated    SensorAvailability = "emulated" // Wine registry
	SensorNative      SensorAvailability = "native"
	SensorUnavailable SensorAvailability = "unavailable"
)

// SensorBackend identifies which sensor implementation is active.
type SensorBackend string

const (
	BackendEBPF    SensorBackend = "ebpf"
	BackendStrace  SensorBackend = "strace"
	BackendETW     SensorBackend = "etw"
	BackendSysmon  SensorBackend = "sysmon"
	BackendWMI     SensorBackend = "wmi"
	BackendPollNet SensorBackend = "poll_net" // Get-NetTCPConnection polling
	BackendNone    SensorBackend = "none"
)

// PlatformContext is stamped on every baseline and observation.
type PlatformContext struct {
	DetectedPlatform ExecutionContext   `json:"detected_platform"`
	HostPlatform     string             `json:"host_platform"`
	InteropLayer     string             `json:"interop_layer"`
	KernelVersion    string             `json:"kernel_version"`
	OSVersion        string             `json:"os_version"`
	WineVersion      *string            `json:"wine_version,omitempty"`
	WSLBuild         *string            `json:"wsl_build,omitempty"`
	ContainerRuntime *string            `json:"container_runtime,omitempty"`
	Capabilities     SensorCapabilities `json:"sensor_capabilities"`
}

// SensorCapabilities describes what this context can observe and how.
type SensorCapabilities struct {
	Syscalls        SensorAvailability `json:"syscalls"`
	Network         SensorAvailability `json:"network"`
	Filesystem      SensorAvailability `json:"filesystem"`
	Registry        SensorAvailability `json:"registry"`
	Memory          SensorAvailability `json:"memory"`
	InteropFS       bool               `json:"interop_filesystem"`
	ActiveBackend   SensorBackend      `json:"active_backend"`
	EBPFAvailable   bool               `json:"ebpf_available"`
	EBPFKernelMin   bool               `json:"ebpf_kernel_min"`  // >= 4.15
	EBPFRingBuffer  bool               `json:"ebpf_ring_buffer"` // >= 5.8
	StraceAvailable bool               `json:"strace_available"`
}

// ─── Target Process ──────────────────────────────────────────────────────────

// TargetProcess describes the process under observation.
type TargetProcess struct {
	Name      string   `json:"process_name"`
	Path      string   `json:"process_path"`
	SHA256    string   `json:"sha256"`
	MD5       string   `json:"md5"`
	Args      []string `json:"argv"`
	EnvOfNote []string `json:"env_vars_of_interest,omitempty"`
	UID       int      `json:"run_as_uid"`
	User      string   `json:"run_as_user"`
}

// ─── Baseline Quality ────────────────────────────────────────────────────────

type BaselineConfidence string

const (
	ConfidenceHigh   BaselineConfidence = "high"   // 3+ consistent runs
	ConfidenceMedium BaselineConfidence = "medium" // 2 runs or minor variance
	ConfidenceLow    BaselineConfidence = "low"    // single run
)

type RunRecord struct {
	RunID            int       `json:"run_id"`
	PID              int       `json:"pid"`
	StartedAt        time.Time `json:"started_at"`
	EndedAt          time.Time `json:"ended_at"`
	ExitCode         int       `json:"exit_code"`
	AnomaliesVsPrior []string  `json:"anomalies_vs_prior,omitempty"`
}

type BaselineQuality struct {
	RunCount        int                `json:"run_count"`
	DurationSeconds int                `json:"run_duration_seconds"`
	Runs            []RunRecord        `json:"runs"`
	VarianceNotes   []string           `json:"variance_notes,omitempty"`
	Confidence      BaselineConfidence `json:"confidence"`
}

// ─── Syscall Observations ────────────────────────────────────────────────────

type SyscallRecord struct {
	Count             int      `json:"count"`
	FirstSeenOffsetMS int64    `json:"first_seen_offset_ms"`
	LastSeenOffsetMS  int64    `json:"last_seen_offset_ms"`
	ArgsSample        []string `json:"args_sample,omitempty"`

	// Exit-side data, populated from the sys_exit probe (schema >= 2.1.0).
	ExitCount      int     `json:"exit_count"`           // completed invocations observed
	ErrorCount     int     `json:"error_count"`          // exits with a negative return value
	RetSample      []int64 `json:"ret_sample,omitempty"` // sample of return values
	MaxLatencyNS   int64   `json:"max_latency_ns"`       // slowest enter→exit seen
	TotalLatencyNS int64   `json:"total_latency_ns"`     // sum over ExitCount (mean = total/exit)
}

type SyscallPercentiles struct {
	P50 map[string]int `json:"p50"`
	P95 map[string]int `json:"p95"`
	P99 map[string]int `json:"p99"`
}

// SyscallsObservation covers all syscall-level data.
// Wine contexts additionally populate WineLayerSignatures.
type SyscallsObservation struct {
	Observed                map[string]SyscallRecord `json:"observed"`
	SequencePatterns        []string                 `json:"sequence_patterns,omitempty"`
	FrequencyPercentiles    SyscallPercentiles       `json:"frequency_percentiles"`
	SuspiciousNeverExpected []string                 `json:"suspicious_never_expected"`
	WineLayerSignatures     []string                 `json:"wine_layer_signatures,omitempty"`
}

// ─── Network Observations ────────────────────────────────────────────────────

type ListeningPort struct {
	Port              int    `json:"port"`
	Proto             string `json:"proto"`
	Address           string `json:"address"`
	FirstSeenOffsetMS int64  `json:"first_seen_offset_ms"`
	Expected          bool   `json:"expected"`
}

type OutboundConnection struct {
	DestinationIP     string `json:"destination_ip"`
	DestinationPort   int    `json:"destination_port"`
	Proto             string `json:"proto"`
	DNSName           string `json:"dns_name,omitempty"`
	BytesSent         int64  `json:"bytes_sent"`
	BytesReceived     int64  `json:"bytes_received"`
	FirstSeenOffsetMS int64  `json:"first_seen_offset_ms"`
}

type DNSQuery struct {
	Query             string `json:"query"`
	Response          string `json:"response"`
	FirstSeenOffsetMS int64  `json:"first_seen_offset_ms"`
}

// RawSocket describes an AF_PACKET or SOCK_RAW socket held by the observed
// process — the two socket classes a SLEEPWALKER-style listener uses, and
// which never produce a row in /proc/net/{tcp,udp}. A "packet" family socket
// bound to ALL interfaces (Interface == "*") is the specific shape of a
// promiscuous-capture trigger listener.
type RawSocket struct {
	Family            string `json:"family"`              // "packet" (AF_PACKET) or "raw" (SOCK_RAW over IP)
	Protocol          string `json:"protocol"`            // packet: EtherType hex (e.g. "0x0003" = ETH_P_ALL); raw: IP protocol name
	Interface         string `json:"interface,omitempty"` // packet sockets only; "*" = bound to every interface (ifindex 0)
	Inode             string `json:"inode"`
	FirstSeenOffsetMS int64  `json:"first_seen_offset_ms"`
}

type NetworkObservation struct {
	ListeningPorts      []ListeningPort      `json:"listening_ports"`
	OutboundConnections []OutboundConnection `json:"outbound_connections"`
	DNSQueries          []DNSQuery           `json:"dns_queries"`
	RawSockets          []RawSocket          `json:"raw_sockets,omitempty"`
	// PromiscuousInterfaces lists interfaces with IFF_PROMISC set at capture
	// time. This is SYSTEM-WIDE state, not attributable to the observed
	// process on its own — another process or a legitimate capture tool could
	// be the cause. It's meaningful as corroborating context, weighted most
	// heavily alongside a RawSocket of family "packet" held by this same
	// process. See analysis.diffNetwork for how the two are combined.
	PromiscuousInterfaces []string `json:"promiscuous_interfaces,omitempty"`
	WSLForwardedPorts     []int    `json:"wsl_forwarded_ports,omitempty"`
	InteropNetworkCalls   []string `json:"interop_network_calls,omitempty"`
}

// ─── Filesystem Observations ─────────────────────────────────────────────────

type FilePath struct {
	Path           string `json:"path"`
	NormalizedPath string `json:"normalized_path"`
	Count          int    `json:"count"`
	Sensitive      bool   `json:"sensitive"`
	InteropPath    bool   `json:"interop_path"` // /mnt/c or Wine virtual FS
}

type InteropFSAccess struct {
	WindowsPathsFromWSL []string `json:"windows_paths_from_wsl,omitempty"`
	LinuxPathsFromWine  []string `json:"linux_paths_from_wine,omitempty"`
}

type FilesystemObservation struct {
	PathsRead       []FilePath      `json:"paths_read"`
	PathsWritten    []FilePath      `json:"paths_written"`
	PathsCreated    []FilePath      `json:"paths_created"`
	PathsDeleted    []FilePath      `json:"paths_deleted"`
	ExecsTouched    []FilePath      `json:"executables_touched"`
	TempPatterns    []string        `json:"temp_patterns,omitempty"`
	InteropFSAccess InteropFSAccess `json:"interop_filesystem_access"`
}

// ─── Registry Observations ───────────────────────────────────────────────────

type RegistryKey struct {
	Key       string `json:"key"`
	ValueName string `json:"value_name,omitempty"`
	Count     int    `json:"count"`
	Sensitive bool   `json:"sensitive"`
}

type RegistryObservation struct {
	Available              bool               `json:"available"`
	Context                SensorAvailability `json:"context"` // native | emulated | unavailable
	KeysRead               []RegistryKey      `json:"keys_read"`
	KeysWritten            []RegistryKey      `json:"keys_written"`
	KeysCreated            []RegistryKey      `json:"keys_created"`
	KeysDeleted            []RegistryKey      `json:"keys_deleted"`
	PersistencePathTouched bool               `json:"persistence_paths_touched"`
}

// ─── Process Behavior ────────────────────────────────────────────────────────

type ChildProcess struct {
	Name              string   `json:"name"`
	Path              string   `json:"path"`
	SHA256            string   `json:"sha256,omitempty"`
	Args              []string `json:"argv,omitempty"`
	UID               int      `json:"uid"`
	FirstSeenOffsetMS int64    `json:"first_seen_offset_ms"`
}

type PrivilegeChange struct {
	FromUID  int    `json:"from_uid"`
	ToUID    int    `json:"to_uid"`
	Syscall  string `json:"syscall"`
	OffsetMS int64  `json:"offset_ms"`
}

type ProcessObservation struct {
	ChildrenSpawned   []ChildProcess    `json:"children_spawned"`
	SignalsSent       []string          `json:"signals_sent,omitempty"`
	ProcFSReads       []string          `json:"proc_filesystem_reads,omitempty"` // /proc/<other_pid> reads
	PrivilegeChanges  []PrivilegeChange `json:"privilege_changes,omitempty"`
	CapabilitiesUsed  []string          `json:"capabilities_used,omitempty"`
	InjectionDetected bool              `json:"injections_detected"`
}

// ─── Memory Observations ─────────────────────────────────────────────────────

type MemoryRegion struct {
	AddressRange string `json:"address_range"`
	BackedBy     string `json:"backed_by"` // "file" or "anonymous"
	Suspicious   bool   `json:"suspicious"`
}

type MemoryObservation struct {
	PeakRSSKB         int64          `json:"peak_rss_kb"`
	HeapGrowthKB      int64          `json:"heap_growth_kb"`
	ExecutableRegions []MemoryRegion `json:"executable_regions"`
	LargeAllocations  []int64        `json:"large_allocations,omitempty"`
	MappedFiles       []string       `json:"mapped_files,omitempty"`
}

// ─── Anomaly Configuration ───────────────────────────────────────────────────

// AnomalyType is a stable identifier for a class of deviation.
type AnomalyType string

const (
	AnomalyNewListeningPort        AnomalyType = "new_listening_port"
	AnomalyNewOutboundConnection   AnomalyType = "new_outbound_connection"
	AnomalyExecutableWritten       AnomalyType = "executable_written"
	AnomalyPrivilegeEscalation     AnomalyType = "privilege_escalation"
	AnomalyNewChildProcess         AnomalyType = "new_child_process"
	AnomalyRegistryPersistence     AnomalyType = "registry_persistence_path"
	AnomalyProcFSReadOtherPID      AnomalyType = "proc_filesystem_read_other_pid"
	AnomalyWineEscapeSyscall       AnomalyType = "wine_escape_syscall"
	AnomalyWSLInteropFSWrite       AnomalyType = "wsl_interop_filesystem_write"
	AnomalyUnexpectedSyscall       AnomalyType = "unexpected_syscall"
	AnomalyExecMemoryAnonymous     AnomalyType = "executable_memory_anonymous"
	AnomalyDNSQuerySuspicious      AnomalyType = "dns_query_suspicious"
	AnomalyChildExecMismatch       AnomalyType = "child_process_hash_mismatch"
	AnomalyRawSocketOpened         AnomalyType = "raw_socket_opened"
	AnomalyPromiscuousModeObserved AnomalyType = "promiscuous_mode_observed"
)

// DefaultAnomalyWeights are the out-of-the-box risk weights (0-10).
// Override in anomaly_config per-baseline as needed.
var DefaultAnomalyWeights = map[AnomalyType]int{
	AnomalyNewListeningPort:        9,
	AnomalyNewOutboundConnection:   7,
	AnomalyExecutableWritten:       10,
	AnomalyPrivilegeEscalation:     10,
	AnomalyNewChildProcess:         6,
	AnomalyRegistryPersistence:     9,
	AnomalyProcFSReadOtherPID:      8,
	AnomalyWineEscapeSyscall:       10,
	AnomalyWSLInteropFSWrite:       7,
	AnomalyUnexpectedSyscall:       8,
	AnomalyExecMemoryAnonymous:     9,
	AnomalyDNSQuerySuspicious:      7,
	AnomalyChildExecMismatch:       8,
	AnomalyRawSocketOpened:         9,
	AnomalyPromiscuousModeObserved: 8,
}

// DefaultMITREMappings maps anomaly types to ATT&CK technique IDs.
var DefaultMITREMappings = map[AnomalyType]string{
	AnomalyNewListeningPort:        "T1571",
	AnomalyNewOutboundConnection:   "T1041",
	AnomalyExecutableWritten:       "T1027",
	AnomalyPrivilegeEscalation:     "T1548",
	AnomalyNewChildProcess:         "T1059",
	AnomalyRegistryPersistence:     "T1547",
	AnomalyProcFSReadOtherPID:      "T1057",
	AnomalyWineEscapeSyscall:       "T1106",
	AnomalyWSLInteropFSWrite:       "T1564.006",
	AnomalyUnexpectedSyscall:       "T1106",
	AnomalyExecMemoryAnonymous:     "T1055",
	AnomalyDNSQuerySuspicious:      "T1071",
	AnomalyChildExecMismatch:       "T1036",
	AnomalyRawSocketOpened:         "T1040",
	AnomalyPromiscuousModeObserved: "T1040",
}

type NoiseSuppress struct {
	HighFrequencyBenignSyscalls []string `json:"high_frequency_benign_syscalls"`
	KnownInteropPaths           []string `json:"known_interop_paths"`
}

var DefaultNoiseSuppress = NoiseSuppress{
	HighFrequencyBenignSyscalls: []string{
		"mmap", "mprotect", "brk", "futex", "epoll_wait",
		"poll", "select", "nanosleep", "clock_gettime",
	},
	KnownInteropPaths: []string{
		"/mnt/c/Windows/System32",
		"/mnt/c/Windows/SysWOW64",
	},
}

type AnomalyConfig struct {
	Weights       map[AnomalyType]int    `json:"weights"`
	MITREMappings map[AnomalyType]string `json:"mitre_mappings"`
	SuppressNoise NoiseSuppress          `json:"suppress_noise"`
}

// ─── Baseline ────────────────────────────────────────────────────────────────

// ScrutinyMeta is the top-level envelope stamped on every baseline file.
type ScrutinyMeta struct {
	SchemaVersion string          `json:"schema_version"`
	ToolVersion   string          `json:"tool_version"`
	BaselineID    string          `json:"baseline_id"`
	CreatedAt     time.Time       `json:"created_at"`
	Platform      PlatformContext `json:"platform_context"`
	Target        TargetProcess   `json:"target"`
	Quality       BaselineQuality `json:"baseline_quality"`
}

// Baseline is the complete baseline record. Immutable once written.
type Baseline struct {
	Scrutiny   ScrutinyMeta          `json:"scrutiny"`
	Syscalls   SyscallsObservation   `json:"syscalls"`
	Network    NetworkObservation    `json:"network"`
	Filesystem FilesystemObservation `json:"filesystem"`
	Registry   RegistryObservation   `json:"registry"`
	Process    ProcessObservation    `json:"process"`
	Memory     MemoryObservation     `json:"memory"`
	AnomalyCfg AnomalyConfig         `json:"anomaly_config"`
}

// NewBaseline creates a Baseline with sensible defaults populated.
func NewBaseline(platform PlatformContext, target TargetProcess) *Baseline {
	return &Baseline{
		Scrutiny: ScrutinyMeta{
			SchemaVersion: SchemaVersion,
			ToolVersion:   ToolVersion,
			BaselineID:    uuid.New().String(),
			CreatedAt:     time.Now().UTC(),
			Platform:      platform,
			Target:        target,
			Quality: BaselineQuality{
				RunCount:        0,
				DurationSeconds: 120,
				Confidence:      ConfidenceLow,
			},
		},
		Syscalls: SyscallsObservation{
			Observed: make(map[string]SyscallRecord),
			SuspiciousNeverExpected: []string{
				"ptrace", "process_vm_readv", "process_vm_writev",
				"init_module", "finit_module", "delete_module",
				"kexec_load", "kexec_file_load",
			},
		},
		Network:    NetworkObservation{},
		Filesystem: FilesystemObservation{},
		Registry: RegistryObservation{
			Available: platform.Capabilities.Registry != SensorUnavailable,
			Context:   platform.Capabilities.Registry,
		},
		Process: ProcessObservation{},
		Memory:  MemoryObservation{},
		AnomalyCfg: AnomalyConfig{
			Weights:       DefaultAnomalyWeights,
			MITREMappings: DefaultMITREMappings,
			SuppressNoise: DefaultNoiseSuppress,
		},
	}
}

// ─── Observation ─────────────────────────────────────────────────────────────

// Observation is structurally identical to Baseline but carries
// the baseline ID it was compared against and context match metadata.
type Observation struct {
	Baseline
	ObservationID string          `json:"observation_id"`
	BaselineRef   string          `json:"baseline_id"`
	ContextMatch  bool            `json:"context_match"`
	ContextDelta  PlatformContext `json:"context_delta,omitempty"`
}

// NewObservation creates an Observation linked to a given baseline.
func NewObservation(baselineID string, platform PlatformContext, target TargetProcess) *Observation {
	b := NewBaseline(platform, target)
	return &Observation{
		Baseline:      *b,
		ObservationID: uuid.New().String(),
		BaselineRef:   baselineID,
		ContextMatch:  true,
	}
}

// ─── Analysis Output ─────────────────────────────────────────────────────────

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

type Verdict string

const (
	VerdictClean      Verdict = "clean"
	VerdictSuspicious Verdict = "suspicious"
	VerdictMalicious  Verdict = "malicious"
)

// Dimension identifies which observation category an anomaly belongs to.
type Dimension string

const (
	DimNetwork    Dimension = "network"
	DimFilesystem Dimension = "filesystem"
	DimSyscalls   Dimension = "syscalls"
	DimProcess    Dimension = "process"
	DimRegistry   Dimension = "registry"
	DimMemory     Dimension = "memory"
)

type Anomaly struct {
	AnomalyID         string      `json:"anomaly_id"`
	Dimension         Dimension   `json:"dimension"`
	Type              AnomalyType `json:"type"`
	Severity          Severity    `json:"severity"`
	Weight            int         `json:"weight"`
	MITRETechnique    string      `json:"mitre_technique"`
	Description       string      `json:"description"`
	BaselineValue     interface{} `json:"baseline_value"`
	ObservedValue     interface{} `json:"observed_value"`
	FirstSeenOffsetMS int64       `json:"first_seen_offset_ms"`
	Suppressed        bool        `json:"suppressed"`
	SuppressionReason *string     `json:"suppression_reason,omitempty"`
}

type SeverityBreakdown struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

type AnalysisSummary struct {
	TotalAnomalies   int               `json:"total_anomalies"`
	BySeverity       SeverityBreakdown `json:"by_severity"`
	ByDimension      map[Dimension]int `json:"by_dimension"`
	ByMITRETechnique map[string]int    `json:"by_mitre_technique"`
}

// WazuhAlert is the pre-formatted payload for direct Wazuh forwarding.
type WazuhAlert struct {
	RuleID          int         `json:"rule_id"`
	RuleLevel       int         `json:"rule_level"`
	RuleDescription string      `json:"rule_description"`
	Data            interface{} `json:"data"`
}

// AnalysisResult is what the analysis engine produces.
type AnalysisResult struct {
	AnalysisID    string             `json:"analysis_id"`
	BaselineID    string             `json:"baseline_id"`
	ObservationID string             `json:"observation_id"`
	AnalyzedAt    time.Time          `json:"analyzed_at"`
	RiskScore     int                `json:"overall_risk_score"`
	Verdict       Verdict            `json:"verdict"`
	Confidence    BaselineConfidence `json:"confidence"`
	ContextMatch  bool               `json:"context_match"`
	Anomalies     []Anomaly          `json:"anomalies"`
	Summary       AnalysisSummary    `json:"summary"`
	WazuhAlert    WazuhAlert         `json:"wazuh_alert"`
}
