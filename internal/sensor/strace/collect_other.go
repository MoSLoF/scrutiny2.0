//go:build !linux

package strace

import (
	"fmt"
	"time"

	"github.com/MoSLoF/scrutiny2.0/internal/schema"
)

// Collect is unavailable off Linux (strace and ptrace are Linux-only). The CLI
// never selects the strace backend on other platforms, but this keeps the
// package cross-compilable.
func Collect(pid uint32, duration time.Duration, platformCtx schema.PlatformContext) (*schema.SyscallsObservation, *schema.FilesystemObservation, error) {
	return nil, nil, fmt.Errorf("strace backend is Linux-only")
}
