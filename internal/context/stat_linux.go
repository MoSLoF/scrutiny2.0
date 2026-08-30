//go:build linux

package context

import (
	"os"
	"strconv"
	"syscall"
)

// syscallStat is the platform-specific stat struct alias.
type syscallStat = syscall.Stat_t

// cgroupNSInode returns the cgroup namespace inode for container detection.
func cgroupNSInode() string {
	info, err := os.Lstat("/proc/self/ns/cgroup")
	if err != nil {
		return ""
	}
	return strconv.FormatUint(info.Sys().(*syscallStat).Ino, 10)
}
