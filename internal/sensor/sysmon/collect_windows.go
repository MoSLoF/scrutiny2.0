//go:build windows

package sysmon

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Collect waits out the capture window, then queries the Sysmon operational log
// for events in that window and maps them onto the schema for the target PID
// (and its spawned children). Sysmon logs continuously, so a post-hoc query
// over the window is sufficient and far simpler than a live subscription.
func Collect(pid int, duration time.Duration) (Result, error) {
	time.Sleep(duration)
	events, err := queryEvents(int(duration.Seconds()) + 2) // +2s margin
	if err != nil {
		return Result{}, err
	}
	return MapEvents(events, pid), nil
}

// Available reports whether a Sysmon service is running.
func Available() bool {
	for _, svc := range []string{"Sysmon64", "Sysmon"} {
		out, err := exec.Command("sc", "query", svc).Output()
		if err == nil && strings.Contains(string(out), "RUNNING") {
			return true
		}
	}
	return false
}

// queryEvents reads Sysmon events from the last sinceSecs seconds, flattening
// each event's EventData into a name→value map, emitted as JSON.
func queryEvents(sinceSecs int) ([]SysmonEvent, error) {
	ps := fmt.Sprintf(`$s=(Get-Date).AddSeconds(-%d); `+
		`$ev=Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; StartTime=$s} -ErrorAction SilentlyContinue; `+
		`$out=foreach($e in $ev){ $x=[xml]$e.ToXml(); $d=@{}; foreach($n in $x.Event.EventData.Data){ if($n.Name){ $d[$n.Name]="$($n.'#text')" } }; [pscustomobject]@{Id=[int]$e.Id; Data=$d} }; `+
		`$out | ConvertTo-Json -Depth 4 -Compress`, sinceSecs)

	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", ps).Output()
	if err != nil {
		return nil, fmt.Errorf("querying Sysmon log (admin? Sysmon installed?): %w", err)
	}
	return decodeEvents(out)
}

// decodeEvents parses ConvertTo-Json output, which is `null` for zero events, a
// bare object for exactly one, and an array otherwise.
func decodeEvents(b []byte) ([]SysmonEvent, error) {
	s := bytes.TrimSpace(b)
	if len(s) == 0 || string(s) == "null" {
		return nil, nil
	}

	type raw struct {
		ID   int                    `json:"Id"`
		Data map[string]interface{} `json:"Data"`
	}
	var arr []raw
	if s[0] == '[' {
		if err := json.Unmarshal(s, &arr); err != nil {
			return nil, fmt.Errorf("decoding Sysmon events: %w", err)
		}
	} else {
		var one raw
		if err := json.Unmarshal(s, &one); err != nil {
			return nil, fmt.Errorf("decoding Sysmon event: %w", err)
		}
		arr = []raw{one}
	}

	events := make([]SysmonEvent, 0, len(arr))
	for _, r := range arr {
		data := make(map[string]string, len(r.Data))
		for k, v := range r.Data {
			if v != nil {
				data[k] = fmt.Sprint(v)
			}
		}
		events = append(events, SysmonEvent{ID: r.ID, Data: data})
	}
	return events, nil
}
