package sysmon

import (
	"sort"

	"github.com/MoSLoF/scrutiny2.0/internal/schema"
)

// sortResult orders every slice deterministically so output (and tests) don't
// depend on event iteration order.
func sortResult(r *Result) {
	sort.Slice(r.Process.ChildrenSpawned, func(i, j int) bool {
		return r.Process.ChildrenSpawned[i].Path < r.Process.ChildrenSpawned[j].Path
	})
	sort.Strings(r.Process.ProcFSReads)

	sort.Slice(r.Network.OutboundConnections, func(i, j int) bool {
		a, b := r.Network.OutboundConnections[i], r.Network.OutboundConnections[j]
		if a.DestinationIP != b.DestinationIP {
			return a.DestinationIP < b.DestinationIP
		}
		return a.DestinationPort < b.DestinationPort
	})
	sort.Slice(r.Network.DNSQueries, func(i, j int) bool {
		return r.Network.DNSQueries[i].Query < r.Network.DNSQueries[j].Query
	})

	sortFiles(r.Filesystem.PathsCreated)
	sortFiles(r.Filesystem.PathsDeleted)

	sortKeys(r.Registry.KeysCreated)
	sortKeys(r.Registry.KeysDeleted)
	sortKeys(r.Registry.KeysWritten)

	sort.Strings(r.Memory.MappedFiles)
}

func sortFiles(f []schema.FilePath) {
	sort.Slice(f, func(i, j int) bool { return f[i].Path < f[j].Path })
}

func sortKeys(k []schema.RegistryKey) {
	sort.Slice(k, func(i, j int) bool { return k[i].Key < k[j].Key })
}
