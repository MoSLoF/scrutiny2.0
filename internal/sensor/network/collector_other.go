//go:build !linux

package network

import (
	"time"

	"github.com/MoSLoF/scrutiny2.0/internal/schema"
)

// Collect is a no-op on non-Linux platforms: the procfs socket tables it reads
// exist only on Linux. Windows network collection belongs to a future ETW /
// Get-NetTCPConnection backend. Returning an empty observation (not an error)
// lets the cross-platform CLI call this unconditionally.
func Collect(pid int, duration time.Duration) (*schema.NetworkObservation, error) {
	return &schema.NetworkObservation{}, nil
}
