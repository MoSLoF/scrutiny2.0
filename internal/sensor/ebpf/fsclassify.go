package ebpf

import (
	"sort"
	"strings"

	"github.com/MoSLoF/scrutiny2.0/internal/schema"
)

// op codes — kept in sync with bpf/syscall_trace.c.
const (
	opOpen   = 0
	opDelete = 1
	opExec   = 2
	opRename = 3
)

// x86_64 open() flag bits (mirrors the F_* defines in the eBPF program).
const (
	fWRONLY = 0x1
	fRDWR   = 0x2
	fCREAT  = 0x40
	fTRUNC  = 0x200
)

// FileAccess is the platform-independent decoding of one file_event, so the
// classification logic can be unit tested without the eBPF ring buffer.
type FileAccess struct {
	SyscallNr int64
	Flags     uint32
	Op        uint8
	Path      string
}

// buckets an access can fall into (a create-for-write lands in two).
const (
	bucketRead = iota
	bucketWritten
	bucketCreated
	bucketDeleted
	bucketExec
)

func bucketsFor(a FileAccess) []int {
	switch a.Op {
	case opDelete:
		return []int{bucketDeleted}
	case opExec:
		return []int{bucketExec}
	case opRename:
		// The destination of a rename is effectively created and modified.
		return []int{bucketCreated, bucketWritten}
	default: // opOpen
		var b []int
		if a.Flags&fCREAT != 0 {
			b = append(b, bucketCreated)
		}
		if a.Flags&(fWRONLY|fRDWR|fTRUNC) != 0 {
			b = append(b, bucketWritten)
		}
		if len(b) == 0 {
			b = append(b, bucketRead)
		}
		return b
	}
}

// buildFilesystem folds a stream of file accesses into a FilesystemObservation:
// deduplicated per (bucket, path) with occurrence counts, sensitivity and
// interop-boundary flags, and a deterministic ordering.
func buildFilesystem(accesses []FileAccess) *schema.FilesystemObservation {
	type key struct {
		bucket int
		path   string
	}
	counts := map[key]int{}
	for _, a := range accesses {
		if a.Path == "" {
			continue
		}
		for _, bkt := range bucketsFor(a) {
			counts[key{bkt, a.Path}]++
		}
	}

	obs := &schema.FilesystemObservation{}
	add := func(dst *[]schema.FilePath, path string, count int) {
		*dst = append(*dst, schema.FilePath{
			Path:           path,
			NormalizedPath: path,
			Count:          count,
			Sensitive:      isSensitivePath(path),
			InteropPath:    isInteropPath(path),
		})
	}
	for k, c := range counts {
		switch k.bucket {
		case bucketRead:
			add(&obs.PathsRead, k.path, c)
		case bucketWritten:
			add(&obs.PathsWritten, k.path, c)
		case bucketCreated:
			add(&obs.PathsCreated, k.path, c)
		case bucketDeleted:
			add(&obs.PathsDeleted, k.path, c)
		case bucketExec:
			add(&obs.ExecsTouched, k.path, c)
		}
	}

	for _, list := range [][]schema.FilePath{
		obs.PathsRead, obs.PathsWritten, obs.PathsCreated, obs.PathsDeleted, obs.ExecsTouched,
	} {
		sort.Slice(list, func(i, j int) bool { return list[i].Path < list[j].Path })
	}
	return obs
}

// sensitivePrefixes / sensitiveContains flag paths that malware commonly reads
// or tampers with (credentials, persistence, shell history).
var sensitivePrefixes = []string{
	"/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/gshadow",
	"/etc/ssh", "/etc/crontab", "/etc/cron.", "/var/spool/cron",
	"/root/", "/boot/",
}

var sensitiveContains = []string{
	"/.ssh/", "/.bash_history", "/.aws/credentials", "/.docker/config",
	"/authorized_keys",
}

func isSensitivePath(path string) bool {
	for _, p := range sensitivePrefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	for _, c := range sensitiveContains {
		if strings.Contains(path, c) {
			return true
		}
	}
	return false
}

// isInteropPath reports whether a path crosses the WSL interop boundary
// (the Windows filesystem mounted under /mnt).
func isInteropPath(path string) bool {
	return strings.HasPrefix(path, "/mnt/")
}
