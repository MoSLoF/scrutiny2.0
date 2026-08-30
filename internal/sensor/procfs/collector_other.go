//go:build !linux

package procfs

import (
	"time"

	"github.com/MoSLoF/scrutiny2.0/internal/schema"
)

// CollectProcess and CollectMemory are no-ops on non-Linux platforms: they read
// /proc, which exists only on Linux. Windows lineage/memory sensing belongs to
// a future ETW/WMI backend. Returning empty observations (not errors) lets the
// cross-platform CLI call these unconditionally.

func CollectProcess(pid int, duration time.Duration) (*schema.ProcessObservation, error) {
	return &schema.ProcessObservation{}, nil
}

func CollectMemory(pid int, duration time.Duration) (*schema.MemoryObservation, error) {
	return &schema.MemoryObservation{}, nil
}
