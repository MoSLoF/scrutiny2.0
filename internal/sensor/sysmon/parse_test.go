package sysmon

import "testing"

func ev(id int, kv ...string) SysmonEvent {
	d := map[string]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		d[kv[i]] = kv[i+1]
	}
	return SysmonEvent{ID: id, Data: d}
}

const target = 1000

func TestMap_ProcessCreateChild(t *testing.T) {
	r := MapEvents([]SysmonEvent{
		ev(1, "ProcessId", "2000", "ParentProcessId", "1000",
			"Image", `C:\Windows\System32\cmd.exe`, "CommandLine", `cmd.exe /c whoami`,
			"Hashes", "MD5=ABC,SHA256=DEADBEEF"),
		// a process NOT spawned by the target — must be ignored
		ev(1, "ProcessId", "3000", "ParentProcessId", "42", "Image", `C:\other.exe`),
	}, target)

	if len(r.Process.ChildrenSpawned) != 1 {
		t.Fatalf("children = %d, want 1", len(r.Process.ChildrenSpawned))
	}
	c := r.Process.ChildrenSpawned[0]
	if c.Name != "cmd.exe" || c.Path != `C:\Windows\System32\cmd.exe` {
		t.Errorf("child = %+v, want cmd.exe", c)
	}
	if c.SHA256 != "deadbeef" {
		t.Errorf("sha256 = %q, want deadbeef", c.SHA256)
	}
	if len(c.Args) == 0 || c.Args[0] != "cmd.exe" {
		t.Errorf("args = %v, want [cmd.exe /c whoami]", c.Args)
	}
}

func TestMap_NetworkConnectOutbound(t *testing.T) {
	r := MapEvents([]SysmonEvent{
		ev(3, "ProcessId", "1000", "Initiated", "true", "Protocol", "tcp",
			"DestinationIp", "8.8.8.8", "DestinationPort", "443", "DestinationHostname", "dns.google"),
		// inbound (Initiated=false) — not an outbound connection
		ev(3, "ProcessId", "1000", "Initiated", "false", "Protocol", "tcp",
			"DestinationIp", "10.0.0.5", "DestinationPort", "12345"),
	}, target)

	if len(r.Network.OutboundConnections) != 1 {
		t.Fatalf("outbound = %d, want 1", len(r.Network.OutboundConnections))
	}
	oc := r.Network.OutboundConnections[0]
	if oc.DestinationIP != "8.8.8.8" || oc.DestinationPort != 443 || oc.DNSName != "dns.google" {
		t.Errorf("outbound = %+v", oc)
	}
}

func TestMap_FileCreateAndDelete(t *testing.T) {
	r := MapEvents([]SysmonEvent{
		ev(11, "ProcessId", "1000", "TargetFilename", `C:\Temp\payload.exe`),
		ev(11, "ProcessId", "1000", "TargetFilename", `C:\Temp\payload.exe`), // dup
		ev(23, "ProcessId", "1000", "TargetFilename", `C:\Temp\evidence.log`),
	}, target)

	if len(r.Filesystem.PathsCreated) != 1 || r.Filesystem.PathsCreated[0].Path != `C:\Temp\payload.exe` {
		t.Errorf("created = %+v, want [payload.exe] (deduped)", r.Filesystem.PathsCreated)
	}
	if len(r.Filesystem.PathsDeleted) != 1 {
		t.Errorf("deleted = %+v, want 1", r.Filesystem.PathsDeleted)
	}
}

func TestMap_RegistryPersistence(t *testing.T) {
	r := MapEvents([]SysmonEvent{
		ev(13, "ProcessId", "1000",
			"TargetObject", `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Evil`),
		ev(13, "ProcessId", "1000",
			"TargetObject", `HKCU\Software\Some\Benign\Setting`),
	}, target)

	if len(r.Registry.KeysWritten) != 2 {
		t.Fatalf("written keys = %d, want 2", len(r.Registry.KeysWritten))
	}
	if !r.Registry.PersistencePathTouched {
		t.Error("a CurrentVersion\\Run write should set PersistencePathTouched")
	}
	if !r.Registry.Available || r.Registry.Context != "native" {
		t.Errorf("registry availability = %+v", r.Registry)
	}
}

// TestMap_SleepwalkerRegistryWeakening models SLEEPWALKER's two host-config
// changes: EveryoneIncludesAnonymous=1 and a NullSessionPipes entry — the
// author's own primary host IOCs.
func TestMap_SleepwalkerRegistryWeakening(t *testing.T) {
	r := MapEvents([]SysmonEvent{
		ev(13, "ProcessId", "1000",
			"TargetObject", `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous`,
			"Details", "DWORD (0x00000001)"),
		ev(13, "ProcessId", "1000",
			"TargetObject", `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\NullSessionPipes`),
	}, target)

	if !r.Registry.SecurityWeakened {
		t.Fatal("EveryoneIncludesAnonymous / NullSessionPipes should set SecurityWeakened")
	}
	if len(r.Registry.KeysWritten) != 2 {
		t.Errorf("written keys = %d, want 2", len(r.Registry.KeysWritten))
	}
	for _, k := range r.Registry.KeysWritten {
		if !k.Sensitive {
			t.Errorf("weakening key %q should be marked sensitive", k.Key)
		}
	}
}

// TestMap_SleepwalkerImageLoad models the side-loaded dpapi.dll appearing as an
// ImageLoad (EID 7) in the host process.
func TestMap_SleepwalkerImageLoad(t *testing.T) {
	r := MapEvents([]SysmonEvent{
		ev(7, "ProcessId", "1000", "Image", `C:\Program Files\ESET\RemoteAdministrator\Agent\ERAAgent.exe`,
			"ImageLoaded", `C:\Program Files\ESET\RemoteAdministrator\Agent\dpapi.dll`,
			"Signed", "false", "SignatureStatus", "Unavailable"),
		ev(7, "ProcessId", "1000", "ImageLoaded", `C:\Windows\System32\dpapi.dll`), // dup path differs; both kept
	}, target)

	if len(r.Memory.MappedFiles) != 2 {
		t.Fatalf("mapped modules = %d, want 2", len(r.Memory.MappedFiles))
	}
	var sideloaded bool
	for _, m := range r.Memory.MappedFiles {
		if m == `C:\Program Files\ESET\RemoteAdministrator\Agent\dpapi.dll` {
			sideloaded = true
		}
	}
	if !sideloaded {
		t.Error("the side-loaded dpapi.dll should appear in MappedFiles")
	}
}

func TestMap_DNSQuery(t *testing.T) {
	r := MapEvents([]SysmonEvent{
		ev(22, "ProcessId", "1000", "QueryName", "evil.example.com", "QueryResults", "1.2.3.4"),
	}, target)
	if len(r.Network.DNSQueries) != 1 || r.Network.DNSQueries[0].Query != "evil.example.com" {
		t.Errorf("dns = %+v", r.Network.DNSQueries)
	}
}

func TestMap_InjectionAndProcessAccess(t *testing.T) {
	r := MapEvents([]SysmonEvent{
		ev(8, "SourceProcessId", "1000", "TargetProcessId", "500", "TargetImage", `C:\Windows\explorer.exe`),
		ev(10, "SourceProcessId", "1000", "TargetProcessId", "600", "TargetImage", `C:\lsass.exe`),
	}, target)
	if !r.Process.InjectionDetected {
		t.Error("CreateRemoteThread from target should set InjectionDetected")
	}
	if len(r.Process.ProcFSReads) != 1 || r.Process.ProcFSReads[0] != `C:\lsass.exe` {
		t.Errorf("process access = %v, want [lsass.exe]", r.Process.ProcFSReads)
	}
}

func TestMap_ChildSubtreeAttribution(t *testing.T) {
	// The target spawns a child; the child's network connect is attributed to
	// the observed subtree.
	r := MapEvents([]SysmonEvent{
		ev(1, "ProcessId", "2000", "ParentProcessId", "1000", "Image", `C:\child.exe`),
		ev(3, "ProcessId", "2000", "Initiated", "true", "Protocol", "tcp",
			"DestinationIp", "9.9.9.9", "DestinationPort", "53"),
	}, target)
	if len(r.Network.OutboundConnections) != 1 {
		t.Errorf("child's outbound connection should be attributed: %+v", r.Network.OutboundConnections)
	}
}

func TestMap_CountsAndIgnoresUnrelated(t *testing.T) {
	r := MapEvents([]SysmonEvent{
		ev(5, "ProcessId", "1000", "Image", `C:\target.exe`), // ProcessTerminate for target — counts, maps to nothing
		ev(5, "ProcessId", "7777", "Image", `C:\unrelated.exe`),
	}, target)
	if r.EventsRead != 2 {
		t.Errorf("events read = %d, want 2", r.EventsRead)
	}
	if r.EventsForPID != 1 {
		t.Errorf("events for target subtree = %d, want 1", r.EventsForPID)
	}
	// Nothing maps from ProcessTerminate.
	if len(r.Process.ChildrenSpawned) != 0 {
		t.Errorf("terminate should not produce children")
	}
}
