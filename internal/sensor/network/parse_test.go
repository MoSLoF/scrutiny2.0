package network

import "testing"

func TestParseHexAddr_IPv4(t *testing.T) {
	ip, port, err := parseHexAddr("0100007F:1F90")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := ip.String(); got != "127.0.0.1" {
		t.Errorf("ip = %s, want 127.0.0.1", got)
	}
	if port != 8080 {
		t.Errorf("port = %d, want 8080", port)
	}
}

func TestParseHexAddr_IPv4Any(t *testing.T) {
	ip, port, err := parseHexAddr("00000000:0000")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := ip.String(); got != "0.0.0.0" {
		t.Errorf("ip = %s, want 0.0.0.0", got)
	}
	if port != 0 {
		t.Errorf("port = %d, want 0", port)
	}
}

func TestParseHexAddr_IPv6Loopback(t *testing.T) {
	ip, port, err := parseHexAddr("00000000000000000000000001000000:0050")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := ip.String(); got != "::1" {
		t.Errorf("ip = %s, want ::1", got)
	}
	if port != 80 {
		t.Errorf("port = %d, want 80", port)
	}
}

// A representative /proc/<pid>/net/tcp snapshot: a listener on 127.0.0.1:8080,
// an established outbound to 127.0.0.1:8080, and a socket owned by a DIFFERENT
// process (inode 99999) that must be filtered out.
const sampleTCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0100007F:C9C2 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 12346 1 0000000000000000 20 4 30 10 -1
   2: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 99999 1 0000000000000000 100 0 0 10 0
`

func TestParseProcNet_FiltersByInode(t *testing.T) {
	own := map[string]bool{"12345": true, "12346": true} // not 99999
	listening, outbound := parseProcNet(sampleTCP, "tcp", own)

	if len(listening) != 1 {
		t.Fatalf("listening = %d, want 1", len(listening))
	}
	if listening[0].Port != 8080 || listening[0].Address != "127.0.0.1" {
		t.Errorf("listening = %+v, want 127.0.0.1:8080", listening[0])
	}
	if len(outbound) != 1 {
		t.Fatalf("outbound = %d, want 1", len(outbound))
	}
	if outbound[0].DestinationPort != 8080 || outbound[0].DestinationIP != "127.0.0.1" {
		t.Errorf("outbound = %+v, want ->127.0.0.1:8080", outbound[0])
	}
}

func TestParseProcNet_SkipsForeignSockets(t *testing.T) {
	// Only the foreign socket's inode is "owned" — but it isn't in our set,
	// so nothing should be attributed to us.
	listening, outbound := parseProcNet(sampleTCP, "tcp", map[string]bool{"11111": true})
	if len(listening) != 0 || len(outbound) != 0 {
		t.Errorf("got %d listening / %d outbound, want 0/0", len(listening), len(outbound))
	}
}

func TestParseProcNet_UDPOnlyConnected(t *testing.T) {
	// A bound-but-unconnected UDP socket (no remote) must NOT be reported;
	// a connected one must be reported as outbound.
	const sampleUDP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000  1000        0 22222 2 0000000000000000 0
   1: 0100007F:CF3A 08080808:0035 01 00000000:00000000 00:00000000 00000000  1000        0 22223 2 0000000000000000 0
`
	own := map[string]bool{"22222": true, "22223": true}
	listening, outbound := parseProcNet(sampleUDP, "udp", own)
	if len(listening) != 0 {
		t.Errorf("udp listening = %d, want 0 (unconnected UDP is noise)", len(listening))
	}
	if len(outbound) != 1 {
		t.Fatalf("udp outbound = %d, want 1", len(outbound))
	}
	if outbound[0].DestinationIP != "8.8.8.8" || outbound[0].DestinationPort != 53 {
		t.Errorf("udp outbound = %+v, want ->8.8.8.8:53", outbound[0])
	}
}
