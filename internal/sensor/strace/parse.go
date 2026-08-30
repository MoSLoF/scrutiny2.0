// Package strace implements the syscall sensor's strace fallback backend, used
// where eBPF can't run: WSL1, kernels below 4.15, hosts without CAP_BPF, or
// locked-down kernels that reject BPF loads. It drives `strace -f -ttt -T`
// against the target and aggregates completed syscalls into the same
// SyscallsObservation the eBPF backend produces, so the analysis pipeline is
// backend-agnostic. Cost is strace's usual 50-100x overhead — this is a
// correctness fallback, not a performance path.
//
// This file holds the pure line parsing and aggregation so it can be unit
// tested without spawning strace; the process driver is in collect_linux.go.
package strace

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/MoSLoF/scrutiny2.0/internal/schema"
)

// suspiciousNeverExpected mirrors the eBPF backend's watch list so analysis is
// backend-agnostic (see analysis.diffSyscalls).
var suspiciousNeverExpected = []string{
	"ptrace", "process_vm_readv", "process_vm_writev",
	"init_module", "finit_module", "delete_module",
	"kexec_load", "kexec_file_load",
}

// event is one completed syscall parsed from an strace line.
type event struct {
	name      string
	tsMicros  int64 // epoch microseconds (from -ttt); 0 if absent
	latencyNS int64 // from -T
	isError   bool  // return was -1 with an errno
	args      string
}

var (
	// "<pid> <sec>.<usec> <body>" (with -f -ttt) or "<sec>.<usec> <body>".
	prefixPidTS = regexp.MustCompile(`^(\d+)\s+(\d+)\.(\d+)\s+(.*)$`)
	prefixTS    = regexp.MustCompile(`^(\d+)\.(\d+)\s+(.*)$`)
	resumedRE   = regexp.MustCompile(`^<\.\.\. (\w+) resumed>`)
	nameRE      = regexp.MustCompile(`^(\w+)\(`)
	durRE       = regexp.MustCompile(`<(\d+)\.(\d+)>\s*$`)
)

// parseLine parses one strace output line. ok is false for signal lines
// (--- SIG... ---), exit lines (+++ ... +++), and unfinished-syscall lines
// (which are counted via their matching "resumed" line instead), so each
// syscall is recorded exactly once.
func parseLine(line string) (event, bool) {
	line = strings.TrimRight(line, "\r\n")

	var tsMicros int64
	body := strings.TrimSpace(line)
	if m := prefixPidTS.FindStringSubmatch(line); m != nil {
		sec, _ := strconv.ParseInt(m[2], 10, 64)
		tsMicros = sec*1_000_000 + fracMicros(m[3])
		body = strings.TrimSpace(m[4])
	} else if m := prefixTS.FindStringSubmatch(line); m != nil {
		sec, _ := strconv.ParseInt(m[1], 10, 64)
		tsMicros = sec*1_000_000 + fracMicros(m[2])
		body = strings.TrimSpace(m[3])
	}

	if strings.HasPrefix(body, "---") || strings.HasPrefix(body, "+++") {
		return event{}, false // signal / exit
	}
	if strings.HasSuffix(body, "<unfinished ...>") {
		return event{}, false // completed by a later "resumed" line
	}

	var name string
	if m := resumedRE.FindStringSubmatch(body); m != nil {
		name = m[1]
	} else if m := nameRE.FindStringSubmatch(body); m != nil {
		name = m[1]
	} else {
		return event{}, false
	}

	eq := strings.LastIndex(body, " = ")
	if eq < 0 {
		return event{}, false // not a completed syscall
	}
	retPart := body[eq+3:]
	isError := strings.HasPrefix(retPart, "-1 E")

	var latencyNS int64
	if m := durRE.FindStringSubmatch(body); m != nil {
		sec, _ := strconv.ParseInt(m[1], 10, 64)
		latencyNS = (sec*1_000_000 + fracMicros(m[2])) * 1000
	}

	args := ""
	if lp := strings.IndexByte(body, '('); lp >= 0 && lp < eq {
		args = body[lp:eq]
		if len(args) > 128 {
			args = args[:128]
		}
	}

	return event{name: name, tsMicros: tsMicros, latencyNS: latencyNS, isError: isError, args: args}, true
}

// record folds one event into the observation. firstTs anchors offsets to the
// first event's timestamp (kept in the same wall-clock domain strace reports).
func record(obs *schema.SyscallsObservation, e event, firstTs *int64) {
	if *firstTs == 0 && e.tsMicros != 0 {
		*firstTs = e.tsMicros
	}
	var offsetMS int64
	if *firstTs != 0 {
		offsetMS = (e.tsMicros - *firstTs) / 1000
	}

	rec, exists := obs.Observed[e.name]
	if !exists {
		rec = schema.SyscallRecord{FirstSeenOffsetMS: offsetMS}
	}
	rec.Count++
	rec.ExitCount++ // an strace line is a completed (returned) syscall
	rec.LastSeenOffsetMS = offsetMS
	rec.TotalLatencyNS += e.latencyNS
	if e.latencyNS > rec.MaxLatencyNS {
		rec.MaxLatencyNS = e.latencyNS
	}
	if e.isError {
		rec.ErrorCount++
	}
	if e.args != "" && len(rec.ArgsSample) < 3 {
		rec.ArgsSample = append(rec.ArgsSample, e.args)
	}
	obs.Observed[e.name] = rec
}

// fracMicros normalizes strace's fractional-second digits (6 under -ttt) to
// microseconds.
func fracMicros(frac string) int64 {
	for len(frac) < 6 {
		frac += "0"
	}
	v, _ := strconv.ParseInt(frac[:6], 10, 64)
	return v
}
