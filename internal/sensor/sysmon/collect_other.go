//go:build !windows

package sysmon

import (
	"fmt"
	"time"
)

// Collect is unavailable off Windows — the Sysmon event log is a Windows
// facility. Kept so the package cross-compiles.
func Collect(pid int, duration time.Duration) (Result, error) {
	return Result{}, fmt.Errorf("Sysmon backend is Windows-only")
}

// Available is always false off Windows.
func Available() bool { return false }
