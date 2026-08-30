//go:build linux

package procfs

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/MoSLoF/scrutiny2.0/internal/schema"
)

const pollInterval = 500 * time.Millisecond

// CollectProcess polls the target's process lineage for the given duration:
// the children it spawns (name/path/uid/sha256/argv) and any effective-UID
// transition (a drop toward root is the privilege-escalation signal).
func CollectProcess(pid int, duration time.Duration) (*schema.ProcessObservation, error) {
	start := time.Now()
	obs := &schema.ProcessObservation{}
	children := map[int]schema.ChildProcess{}
	initialUID, haveUID := readEUID(pid)
	uidFlagged := false

	poll := func() {
		offset := time.Since(start).Milliseconds()
		for _, cpid := range childrenOf(pid) {
			if _, ok := children[cpid]; ok {
				continue
			}
			children[cpid] = childInfo(cpid, offset)
		}
		if haveUID && !uidFlagged {
			if euid, ok := readEUID(pid); ok && euid != initialUID {
				obs.PrivilegeChanges = append(obs.PrivilegeChanges, schema.PrivilegeChange{
					FromUID:  initialUID,
					ToUID:    euid,
					Syscall:  "setuid",
					OffsetMS: offset,
				})
				uidFlagged = true
			}
		}
	}

	poll()
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	deadline := time.After(duration)
	for {
		select {
		case <-deadline:
			for _, c := range children {
				obs.ChildrenSpawned = append(obs.ChildrenSpawned, c)
			}
			sort.Slice(obs.ChildrenSpawned, func(i, j int) bool {
				return obs.ChildrenSpawned[i].Path < obs.ChildrenSpawned[j].Path
			})
			return obs, nil
		case <-ticker.C:
			poll()
		}
	}
}

// CollectMemory polls the target's memory maps for the given duration, unioning
// anonymous executable regions (rwx marked suspicious) and mapped files, and
// tracking peak RSS and RSS growth over the window.
func CollectMemory(pid int, duration time.Duration) (*schema.MemoryObservation, error) {
	obs := &schema.MemoryObservation{}
	regions := map[string]schema.MemoryRegion{}
	mapped := map[string]bool{}
	largeSet := map[int64]bool{}
	initialRSS := readVmKB(pid, "VmRSS")

	poll := func() {
		if data, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid)); err == nil {
			rs, mf, la := parseMaps(string(data))
			for _, r := range rs {
				regions[r.AddressRange] = r
			}
			for _, f := range mf {
				mapped[f] = true
			}
			for _, s := range la {
				largeSet[s] = true
			}
		}
		if hwm := readVmKB(pid, "VmHWM"); hwm > obs.PeakRSSKB {
			obs.PeakRSSKB = hwm
		}
	}

	poll()
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	deadline := time.After(duration)
	for {
		select {
		case <-deadline:
			if final := readVmKB(pid, "VmRSS"); final > 0 && initialRSS > 0 {
				obs.HeapGrowthKB = final - initialRSS
			}
			for _, r := range regions {
				obs.ExecutableRegions = append(obs.ExecutableRegions, r)
			}
			sort.Slice(obs.ExecutableRegions, func(i, j int) bool {
				return obs.ExecutableRegions[i].AddressRange < obs.ExecutableRegions[j].AddressRange
			})
			for f := range mapped {
				obs.MappedFiles = append(obs.MappedFiles, f)
			}
			sort.Strings(obs.MappedFiles)
			for s := range largeSet {
				obs.LargeAllocations = append(obs.LargeAllocations, s)
			}
			sort.Slice(obs.LargeAllocations, func(i, j int) bool { return obs.LargeAllocations[i] < obs.LargeAllocations[j] })
			return obs, nil
		case <-ticker.C:
			poll()
		}
	}
}

// childrenOf returns the direct child PIDs of pid, summed across its threads
// via /proc/<pid>/task/<tid>/children.
func childrenOf(pid int) []int {
	taskDir := fmt.Sprintf("/proc/%d/task", pid)
	tasks, err := os.ReadDir(taskDir)
	if err != nil {
		return nil
	}
	var out []int
	for _, t := range tasks {
		data, err := os.ReadFile(fmt.Sprintf("%s/%s/children", taskDir, t.Name()))
		if err != nil {
			continue
		}
		for _, tok := range strings.Fields(string(data)) {
			if cpid, err := strconv.Atoi(tok); err == nil {
				out = append(out, cpid)
			}
		}
	}
	return out
}

func childInfo(pid int, offset int64) schema.ChildProcess {
	c := schema.ChildProcess{UID: -1, FirstSeenOffsetMS: offset}
	if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid)); err == nil {
		c.Name = strings.TrimSpace(string(b))
	}
	if p, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)); err == nil {
		c.Path = p
	}
	if data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid)); err == nil {
		if euid, ok := parseStatusEUID(string(data)); ok {
			c.UID = euid
		}
	}
	if data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)); err == nil {
		c.Args = splitCmdline(data)
	}
	c.SHA256 = hashExe(pid)
	return c
}

func splitCmdline(data []byte) []string {
	var out []string
	for _, p := range strings.Split(string(data), "\x00") {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// hashExe hashes the child's executable via /proc/<pid>/exe (which reads the
// mapped binary even if the on-disk path was replaced or deleted). Best effort:
// returns "" if the process is gone or unreadable.
func hashExe(pid int) string {
	f, err := os.Open(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

func readEUID(pid int) (int, bool) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, false
	}
	return parseStatusEUID(string(data))
}

func readVmKB(pid int, key string) int64 {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0
	}
	return parseStatusKB(string(data), key)
}
