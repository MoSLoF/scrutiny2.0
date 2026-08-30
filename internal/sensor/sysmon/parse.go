// Package sysmon implements the Windows sensor backend by consuming Sysmon's
// event log (Microsoft-Windows-Sysmon/Operational). Sysmon already does the
// hard kernel telemetry; we map its structured events onto Scrutiny's schema.
// Windows has no syscall table, so this backend populates the process,
// network, filesystem, and registry dimensions directly (not the syscall one).
//
// This file holds the pure event→schema mapping so it can be unit tested with
// fixtures; the event-log query lives in collect_windows.go.
package sysmon

import (
	"strconv"
	"strings"

	"github.com/MoSLoF/scrutiny2.0/internal/schema"
)

// SysmonEvent is one decoded Sysmon event: its numeric ID and its EventData
// name→value pairs (Image, ProcessId, TargetFilename, ...).
type SysmonEvent struct {
	ID   int
	Data map[string]string
}

// Result is what a Sysmon capture window yields across dimensions, plus counts
// for plumbing diagnostics.
type Result struct {
	Process      schema.ProcessObservation
	Network      schema.NetworkObservation
	Filesystem   schema.FilesystemObservation
	Registry     schema.RegistryObservation
	Memory       schema.MemoryObservation
	EventsRead   int
	EventsForPID int
}

// Sysmon event IDs we map.
const (
	eidProcessCreate      = 1
	eidNetworkConnect     = 3
	eidImageLoad          = 7
	eidCreateRemoteThread = 8
	eidProcessAccess      = 10
	eidFileCreate         = 11
	eidRegistryKey        = 12 // add/delete key
	eidRegistrySetValue   = 13
	eidDNSQuery           = 22
	eidFileDelete         = 23
	eidFileDeleteDetected = 26
)

// MapEvents folds a window of Sysmon events into a Result, attributing events to
// the target process and its spawned children (the subtree, analogous to
// strace -f). Deterministic: same input → same output ordering.
func MapEvents(events []SysmonEvent, targetPID int) Result {
	res := Result{
		Registry:   schema.RegistryObservation{Available: true, Context: schema.SensorNative},
		EventsRead: len(events),
	}

	// Pass 1: the target's direct children extend the tracked-PID set.
	tracked := map[int]bool{targetPID: true}
	for _, e := range events {
		if e.ID == eidProcessCreate {
			if ppid, ok := atoi(e.Data["ParentProcessId"]); ok && ppid == targetPID {
				if cpid, ok := atoi(e.Data["ProcessId"]); ok {
					tracked[cpid] = true
				}
			}
		}
	}

	childSeen := map[string]bool{}
	fileCreated := map[string]bool{}
	fileDeleted := map[string]bool{}
	regKeys := map[string]bool{}
	dnsSeen := map[string]bool{}
	moduleSeen := map[string]bool{}

	for _, e := range events {
		pid, _ := atoi(e.Data["ProcessId"])
		srcPID, _ := atoi(e.Data["SourceProcessId"])
		involved := tracked[pid] || srcPID == targetPID
		if e.ID == eidProcessCreate {
			if ppid, _ := atoi(e.Data["ParentProcessId"]); ppid == targetPID {
				involved = true
			}
		}
		if involved {
			res.EventsForPID++
		}

		switch e.ID {
		case eidProcessCreate:
			if ppid, _ := atoi(e.Data["ParentProcessId"]); ppid == targetPID {
				path := e.Data["Image"]
				if !childSeen[path] {
					childSeen[path] = true
					res.Process.ChildrenSpawned = append(res.Process.ChildrenSpawned, schema.ChildProcess{
						Name:   winBase(path),
						Path:   path,
						SHA256: extractHash(e.Data["Hashes"], "SHA256"),
						Args:   splitArgs(e.Data["CommandLine"]),
						UID:    -1, // Windows has no uid; run-as-user is in User
					})
				}
			}

		case eidNetworkConnect:
			if tracked[pid] && strings.EqualFold(e.Data["Initiated"], "true") {
				dport, _ := atoi(e.Data["DestinationPort"])
				res.Network.OutboundConnections = append(res.Network.OutboundConnections, schema.OutboundConnection{
					Proto:           strings.ToLower(e.Data["Protocol"]),
					DestinationIP:   e.Data["DestinationIp"],
					DestinationPort: dport,
					DNSName:         e.Data["DestinationHostname"],
				})
			}

		case eidFileCreate:
			if tracked[pid] {
				if p := e.Data["TargetFilename"]; p != "" && !fileCreated[p] {
					fileCreated[p] = true
					res.Filesystem.PathsCreated = append(res.Filesystem.PathsCreated, filePath(p))
				}
			}

		case eidFileDelete, eidFileDeleteDetected:
			if tracked[pid] {
				if p := e.Data["TargetFilename"]; p != "" && !fileDeleted[p] {
					fileDeleted[p] = true
					res.Filesystem.PathsDeleted = append(res.Filesystem.PathsDeleted, filePath(p))
				}
			}

		case eidRegistryKey:
			if tracked[pid] {
				key := e.Data["TargetObject"]
				if key != "" && !regKeys[key] {
					regKeys[key] = true
					sensitive := isPersistenceKey(key) || isSecurityWeakeningKey(key)
					rk := schema.RegistryKey{Key: key, Count: 1, Sensitive: sensitive}
					if strings.Contains(e.Data["EventType"], "Delete") {
						res.Registry.KeysDeleted = append(res.Registry.KeysDeleted, rk)
					} else {
						res.Registry.KeysCreated = append(res.Registry.KeysCreated, rk)
					}
					flagRegistrySignals(&res.Registry, key)
				}
			}

		case eidRegistrySetValue:
			if tracked[pid] {
				key := e.Data["TargetObject"]
				if key != "" {
					res.Registry.KeysWritten = append(res.Registry.KeysWritten,
						schema.RegistryKey{Key: key, Count: 1, Sensitive: isPersistenceKey(key) || isSecurityWeakeningKey(key)})
					flagRegistrySignals(&res.Registry, key)
				}
			}

		case eidImageLoad:
			if tracked[pid] {
				if img := e.Data["ImageLoaded"]; img != "" && !moduleSeen[img] {
					moduleSeen[img] = true
					res.Memory.MappedFiles = append(res.Memory.MappedFiles, img)
				}
			}

		case eidDNSQuery:
			if tracked[pid] {
				if q := e.Data["QueryName"]; q != "" && !dnsSeen[q] {
					dnsSeen[q] = true
					res.Network.DNSQueries = append(res.Network.DNSQueries, schema.DNSQuery{
						Query: q, Response: e.Data["QueryResults"],
					})
				}
			}

		case eidCreateRemoteThread:
			// The target injecting a thread into ANOTHER process.
			if srcPID == targetPID {
				res.Process.InjectionDetected = true
			}

		case eidProcessAccess:
			// The target opening a handle into another process (inspection).
			if srcPID == targetPID {
				if ti := e.Data["TargetImage"]; ti != "" {
					res.Process.ProcFSReads = append(res.Process.ProcFSReads, ti)
				}
			}
		}
	}

	sortResult(&res)
	return res
}

// ─── helpers ───────────────────────────────────────────────────────────────────

func filePath(p string) schema.FilePath {
	return schema.FilePath{Path: p, NormalizedPath: p, Count: 1}
}

func atoi(s string) (int, bool) {
	v, err := strconv.Atoi(strings.TrimSpace(s))
	return v, err == nil
}

// winBase returns the final path element of a Windows or Unix path.
func winBase(p string) string {
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[i+1:]
	}
	return p
}

// extractHash pulls one algorithm's value from Sysmon's "SHA256=..,MD5=.." field.
func extractHash(hashes, algo string) string {
	for _, part := range strings.Split(hashes, ",") {
		if kv := strings.SplitN(part, "=", 2); len(kv) == 2 && strings.EqualFold(kv[0], algo) {
			return strings.ToLower(strings.TrimSpace(kv[1]))
		}
	}
	return ""
}

func splitArgs(cmdline string) []string {
	if strings.TrimSpace(cmdline) == "" {
		return nil
	}
	return strings.Fields(cmdline)
}

// persistenceSubstrings are registry locations abused for autostart/persistence.
var persistenceSubstrings = []string{
	`\CurrentVersion\Run`,
	`\CurrentVersion\RunOnce`,
	`\Winlogon`,
	`\Image File Execution Options`,
	`\CurrentControlSet\Services`,
	`\CurrentVersion\Explorer\Shell Folders`,
	`\CurrentVersion\Policies\Explorer\Run`,
}

func isPersistenceKey(key string) bool {
	lower := strings.ToLower(key)
	for _, s := range persistenceSubstrings {
		if strings.Contains(lower, strings.ToLower(s)) {
			return true
		}
	}
	return false
}

// securityWeakeningSubstrings are registry locations that loosen host security
// controls rather than establish persistence — chiefly the anonymous-SMB
// weakening SLEEPWALKER performs, plus related "impair defenses" toggles.
var securityWeakeningSubstrings = []string{
	`\Lsa\EveryoneIncludesAnonymous`,
	`\Lsa\RestrictAnonymous`,
	`\Lsa\RestrictAnonymousSAM`,
	`\LanmanServer\Parameters\NullSessionPipes`,
	`\LanmanServer\Parameters\NullSessionShares`,
	`\LanmanServer\Parameters\RestrictNullSessAccess`,
	`\Windows Defender\`, // disabling AV
	`\FirewallPolicy\`,   // disabling firewall
	`\Terminal Server\fDenyTSConnections`,
}

func isSecurityWeakeningKey(key string) bool {
	lower := strings.ToLower(key)
	for _, s := range securityWeakeningSubstrings {
		if strings.Contains(lower, strings.ToLower(s)) {
			return true
		}
	}
	return false
}

// flagRegistrySignals raises the observation-level persistence / security-
// weakening flags for a touched key.
func flagRegistrySignals(r *schema.RegistryObservation, key string) {
	if isPersistenceKey(key) {
		r.PersistencePathTouched = true
	}
	if isSecurityWeakeningKey(key) {
		r.SecurityWeakened = true
	}
}
