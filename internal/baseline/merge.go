// Package baseline merges the observations from multiple baseline capture runs
// into a single union baseline, tracking how many runs each feature appeared in
// so we can report variance and assign a confidence level. A feature seen in
// every run is stable/expected; one seen in only some runs is variable and
// worth noting — a single-run baseline can't tell the difference, which is why
// multi-run baselines exist.
package baseline

import (
	"fmt"
	"sort"
	"strings"

	"github.com/MoSLoF/scrutiny2.0/internal/schema"
)

const maxSamples = 3

// Accumulator folds successive runs into a union baseline.
type Accumulator struct {
	runs int

	syscalls    map[string]schema.SyscallRecord
	syscallRuns map[string]int
	suspicious  []string

	ports    map[string]schema.ListeningPort
	portRuns map[string]int
	conns    map[string]schema.OutboundConnection
	connRuns map[string]int
	raw      map[string]schema.RawSocket
	rawRuns  map[string]int
	promisc  map[string]bool

	filesRead    map[string]schema.FilePath
	filesWritten map[string]schema.FilePath
	filesCreated map[string]schema.FilePath
	filesDeleted map[string]schema.FilePath
	filesExec    map[string]schema.FilePath

	children   map[string]schema.ChildProcess
	privChng   []schema.PrivilegeChange
	privSeen   map[string]bool
	memRegions map[string]schema.MemoryRegion
	mappedMem  map[string]bool
	largeAlloc map[int64]bool
	peakRSS    int64
	heapGrowth int64

	regCreated   map[string]schema.RegistryKey
	regWritten   map[string]schema.RegistryKey
	regDeleted   map[string]schema.RegistryKey
	regAvailable bool
	regPersist   bool
}

// New returns an empty Accumulator.
func New() *Accumulator {
	return &Accumulator{
		syscalls:     map[string]schema.SyscallRecord{},
		syscallRuns:  map[string]int{},
		ports:        map[string]schema.ListeningPort{},
		portRuns:     map[string]int{},
		conns:        map[string]schema.OutboundConnection{},
		connRuns:     map[string]int{},
		raw:          map[string]schema.RawSocket{},
		rawRuns:      map[string]int{},
		promisc:      map[string]bool{},
		filesRead:    map[string]schema.FilePath{},
		filesWritten: map[string]schema.FilePath{},
		filesCreated: map[string]schema.FilePath{},
		filesDeleted: map[string]schema.FilePath{},
		filesExec:    map[string]schema.FilePath{},
		children:     map[string]schema.ChildProcess{},
		privSeen:     map[string]bool{},
		memRegions:   map[string]schema.MemoryRegion{},
		mappedMem:    map[string]bool{},
		largeAlloc:   map[int64]bool{},
		regCreated:   map[string]schema.RegistryKey{},
		regWritten:   map[string]schema.RegistryKey{},
		regDeleted:   map[string]schema.RegistryKey{},
	}
}

// Runs returns how many runs have been folded in.
func (a *Accumulator) Runs() int { return a.runs }

// AddRun folds one run's observations into the accumulator. Any argument may be
// nil (e.g. no syscall backend, or a non-Linux stub).
func (a *Accumulator) AddRun(s *schema.SyscallsObservation, n *schema.NetworkObservation, f *schema.FilesystemObservation,
	p *schema.ProcessObservation, m *schema.MemoryObservation, r *schema.RegistryObservation) {
	a.runs++

	if s != nil {
		if len(s.SuspiciousNeverExpected) > 0 {
			a.suspicious = s.SuspiciousNeverExpected
		}
		for name, rec := range s.Observed {
			a.syscallRuns[name]++
			if cur, ok := a.syscalls[name]; ok {
				a.syscalls[name] = mergeSyscall(cur, rec)
			} else {
				a.syscalls[name] = rec
			}
		}
	}

	if n != nil {
		for _, p := range n.ListeningPorts {
			k := portKey(p)
			if _, ok := a.ports[k]; !ok {
				a.ports[k] = p
			}
			a.portRuns[k]++
		}
		for _, c := range n.OutboundConnections {
			k := connKey(c)
			if _, ok := a.conns[k]; !ok {
				a.conns[k] = c
			}
			a.connRuns[k]++
		}
		for _, r := range n.RawSockets {
			k := rawSockKey(r)
			if _, ok := a.raw[k]; !ok {
				a.raw[k] = r
			}
			a.rawRuns[k]++
		}
		for _, ifname := range n.PromiscuousInterfaces {
			a.promisc[ifname] = true
		}
	}

	if f != nil {
		mergeFiles(a.filesRead, f.PathsRead)
		mergeFiles(a.filesWritten, f.PathsWritten)
		mergeFiles(a.filesCreated, f.PathsCreated)
		mergeFiles(a.filesDeleted, f.PathsDeleted)
		mergeFiles(a.filesExec, f.ExecsTouched)
	}

	if p != nil {
		for _, c := range p.ChildrenSpawned {
			if _, ok := a.children[c.Path]; !ok {
				a.children[c.Path] = c
			}
		}
		for _, pc := range p.PrivilegeChanges {
			k := fmt.Sprintf("%d|%d|%s", pc.FromUID, pc.ToUID, pc.Syscall)
			if !a.privSeen[k] {
				a.privSeen[k] = true
				a.privChng = append(a.privChng, pc)
			}
		}
	}

	if m != nil {
		for _, r := range m.ExecutableRegions {
			a.memRegions[r.AddressRange] = r
		}
		for _, mf := range m.MappedFiles {
			a.mappedMem[mf] = true
		}
		for _, s := range m.LargeAllocations {
			a.largeAlloc[s] = true
		}
		if m.PeakRSSKB > a.peakRSS {
			a.peakRSS = m.PeakRSSKB
		}
		if m.HeapGrowthKB > a.heapGrowth {
			a.heapGrowth = m.HeapGrowthKB
		}
	}

	if r != nil {
		if r.Available {
			a.regAvailable = true
		}
		if r.PersistencePathTouched {
			a.regPersist = true
		}
		for _, k := range r.KeysCreated {
			a.regCreated[k.Key] = k
		}
		for _, k := range r.KeysWritten {
			a.regWritten[k.Key] = k
		}
		for _, k := range r.KeysDeleted {
			a.regDeleted[k.Key] = k
		}
	}
}

// Result is the union of all runs' observations plus variance notes.
type Result struct {
	Syscalls   schema.SyscallsObservation
	Network    schema.NetworkObservation
	Filesystem schema.FilesystemObservation
	Process    schema.ProcessObservation
	Memory     schema.MemoryObservation
	Registry   schema.RegistryObservation
	Notes      []string
}

// Build assembles the merged observations plus human-readable variance notes.
func (a *Accumulator) Build() Result {
	sys := schema.SyscallsObservation{
		Observed:                map[string]schema.SyscallRecord{},
		SuspiciousNeverExpected: a.suspicious,
	}
	for k, v := range a.syscalls {
		sys.Observed[k] = v
	}

	net := schema.NetworkObservation{}
	for _, p := range a.ports {
		net.ListeningPorts = append(net.ListeningPorts, p)
	}
	for _, c := range a.conns {
		net.OutboundConnections = append(net.OutboundConnections, c)
	}
	for _, r := range a.raw {
		net.RawSockets = append(net.RawSockets, r)
	}
	for ifname := range a.promisc {
		net.PromiscuousInterfaces = append(net.PromiscuousInterfaces, ifname)
	}
	sort.Slice(net.ListeningPorts, func(i, j int) bool { return portKey(net.ListeningPorts[i]) < portKey(net.ListeningPorts[j]) })
	sort.Slice(net.OutboundConnections, func(i, j int) bool { return connKey(net.OutboundConnections[i]) < connKey(net.OutboundConnections[j]) })
	sort.Slice(net.RawSockets, func(i, j int) bool { return rawSockKey(net.RawSockets[i]) < rawSockKey(net.RawSockets[j]) })
	sort.Strings(net.PromiscuousInterfaces)

	fs := schema.FilesystemObservation{
		PathsRead:    filesSlice(a.filesRead),
		PathsWritten: filesSlice(a.filesWritten),
		PathsCreated: filesSlice(a.filesCreated),
		PathsDeleted: filesSlice(a.filesDeleted),
		ExecsTouched: filesSlice(a.filesExec),
	}

	proc := schema.ProcessObservation{PrivilegeChanges: a.privChng}
	for _, c := range a.children {
		proc.ChildrenSpawned = append(proc.ChildrenSpawned, c)
	}
	sort.Slice(proc.ChildrenSpawned, func(i, j int) bool {
		return proc.ChildrenSpawned[i].Path < proc.ChildrenSpawned[j].Path
	})

	mem := schema.MemoryObservation{PeakRSSKB: a.peakRSS, HeapGrowthKB: a.heapGrowth}
	for _, r := range a.memRegions {
		mem.ExecutableRegions = append(mem.ExecutableRegions, r)
	}
	sort.Slice(mem.ExecutableRegions, func(i, j int) bool {
		return mem.ExecutableRegions[i].AddressRange < mem.ExecutableRegions[j].AddressRange
	})
	for mf := range a.mappedMem {
		mem.MappedFiles = append(mem.MappedFiles, mf)
	}
	sort.Strings(mem.MappedFiles)
	for s := range a.largeAlloc {
		mem.LargeAllocations = append(mem.LargeAllocations, s)
	}
	sort.Slice(mem.LargeAllocations, func(i, j int) bool { return mem.LargeAllocations[i] < mem.LargeAllocations[j] })

	reg := schema.RegistryObservation{
		Available:              a.regAvailable,
		PersistencePathTouched: a.regPersist,
		Context:                schema.SensorUnavailable,
	}
	if a.regAvailable {
		reg.Context = schema.SensorNative
	}
	reg.KeysCreated = regSlice(a.regCreated)
	reg.KeysWritten = regSlice(a.regWritten)
	reg.KeysDeleted = regSlice(a.regDeleted)

	return Result{
		Syscalls:   sys,
		Network:    net,
		Filesystem: fs,
		Process:    proc,
		Memory:     mem,
		Registry:   reg,
		Notes:      a.varianceNotes(),
	}
}

func regSlice(m map[string]schema.RegistryKey) []schema.RegistryKey {
	if len(m) == 0 {
		return nil
	}
	out := make([]schema.RegistryKey, 0, len(m))
	for _, k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// Confidence maps a run count to a baseline confidence level, and — matching
// ConfidenceHigh's documented "3+ *consistent* runs" — caps at Medium when the
// runs disagreed with each other (hasVariance). A baseline whose features come
// and go across runs isn't something to alert against with high confidence, no
// matter how many runs were captured.
func Confidence(runs int, hasVariance bool) schema.BaselineConfidence {
	c := schema.ConfidenceLow
	switch {
	case runs >= 3:
		c = schema.ConfidenceHigh
	case runs == 2:
		c = schema.ConfidenceMedium
	}
	if hasVariance && c == schema.ConfidenceHigh {
		c = schema.ConfidenceMedium
	}
	return c
}

// ─── internals ─────────────────────────────────────────────────────────────────

func (a *Accumulator) varianceNotes() []string {
	if a.runs <= 1 {
		return nil
	}
	var notes []string

	var unstableSyscalls []string
	for name, c := range a.syscallRuns {
		if c < a.runs {
			unstableSyscalls = append(unstableSyscalls, fmt.Sprintf("%s (%d/%d)", name, c, a.runs))
		}
	}
	if len(unstableSyscalls) > 0 {
		sort.Strings(unstableSyscalls)
		notes = append(notes, "syscalls not seen in every run: "+strings.Join(unstableSyscalls, ", "))
	}

	var unstablePorts []string
	for k, c := range a.portRuns {
		if c < a.runs {
			p := a.ports[k]
			unstablePorts = append(unstablePorts, fmt.Sprintf("%s/%d (%d/%d)", p.Proto, p.Port, c, a.runs))
		}
	}
	if len(unstablePorts) > 0 {
		sort.Strings(unstablePorts)
		notes = append(notes, "listening ports not seen in every run: "+strings.Join(unstablePorts, ", "))
	}

	var unstableRaw []string
	for k, c := range a.rawRuns {
		if c < a.runs {
			r := a.raw[k]
			unstableRaw = append(unstableRaw, fmt.Sprintf("%s/%s (%d/%d)", r.Family, r.Protocol, c, a.runs))
		}
	}
	if len(unstableRaw) > 0 {
		sort.Strings(unstableRaw)
		notes = append(notes, "raw/packet sockets not seen in every run: "+strings.Join(unstableRaw, ", "))
	}

	return notes
}

func mergeSyscall(m, r schema.SyscallRecord) schema.SyscallRecord {
	m.Count += r.Count
	if r.FirstSeenOffsetMS < m.FirstSeenOffsetMS {
		m.FirstSeenOffsetMS = r.FirstSeenOffsetMS
	}
	if r.LastSeenOffsetMS > m.LastSeenOffsetMS {
		m.LastSeenOffsetMS = r.LastSeenOffsetMS
	}
	m.ExitCount += r.ExitCount
	m.ErrorCount += r.ErrorCount
	m.TotalLatencyNS += r.TotalLatencyNS
	if r.MaxLatencyNS > m.MaxLatencyNS {
		m.MaxLatencyNS = r.MaxLatencyNS
	}
	m.ArgsSample = capAppendStr(m.ArgsSample, r.ArgsSample)
	m.RetSample = capAppendI64(m.RetSample, r.RetSample)
	return m
}

func mergeFiles(dst map[string]schema.FilePath, list []schema.FilePath) {
	for _, f := range list {
		if cur, ok := dst[f.NormalizedPath]; ok {
			cur.Count += f.Count
			dst[f.NormalizedPath] = cur
		} else {
			dst[f.NormalizedPath] = f
		}
	}
}

func filesSlice(m map[string]schema.FilePath) []schema.FilePath {
	if len(m) == 0 {
		return nil
	}
	out := make([]schema.FilePath, 0, len(m))
	for _, f := range m {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func capAppendStr(dst, src []string) []string {
	for _, s := range src {
		if len(dst) >= maxSamples {
			break
		}
		dst = append(dst, s)
	}
	return dst
}

func capAppendI64(dst, src []int64) []int64 {
	for _, v := range src {
		if len(dst) >= maxSamples {
			break
		}
		dst = append(dst, v)
	}
	return dst
}

func portKey(p schema.ListeningPort) string {
	return fmt.Sprintf("%s|%s|%d", p.Proto, p.Address, p.Port)
}

func connKey(c schema.OutboundConnection) string {
	return fmt.Sprintf("%s|%s|%d", c.Proto, c.DestinationIP, c.DestinationPort)
}

func rawSockKey(r schema.RawSocket) string {
	return fmt.Sprintf("%s|%s|%s", r.Family, r.Protocol, r.Interface)
}
