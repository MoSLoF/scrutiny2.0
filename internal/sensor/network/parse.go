// Package network collects a process's network behavior — listening ports and
// outbound connections — by polling the procfs socket tables. This is the
// poll_net backend named in the capability model; it needs no eBPF and works
// on native Linux and WSL2 alike (WSL2 runs a real Linux network stack, so
// /proc/<pid>/net is fully populated for Linux processes).
//
// This file holds the pure, platform-independent parsing so it can be unit
// tested anywhere. The file-reading/polling loop lives in collector_linux.go.
package network

import (
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/MoSLoF/scrutiny2.0/internal/schema"
)

// TCP connection states as reported in /proc/net/tcp (see net/tcp_states.h).
const (
	tcpEstablished = 0x01
	tcpSynSent     = 0x02
	tcpListen      = 0x0A
)

// parseHexAddr parses a "HEXADDR:HEXPORT" token from a procfs socket table.
// Addresses are stored as little-endian 32-bit words: 8 hex chars for IPv4,
// 32 for IPv6.
func parseHexAddr(token string) (net.IP, int, error) {
	i := strings.LastIndex(token, ":")
	if i < 0 {
		return nil, 0, fmt.Errorf("no port separator in %q", token)
	}
	addrHex, portHex := token[:i], token[i+1:]

	port, err := strconv.ParseUint(portHex, 16, 32)
	if err != nil {
		return nil, 0, fmt.Errorf("port %q: %w", portHex, err)
	}
	raw, err := hex.DecodeString(addrHex)
	if err != nil {
		return nil, 0, fmt.Errorf("address %q: %w", addrHex, err)
	}

	switch len(raw) {
	case 4:
		// Single little-endian word: reverse the 4 bytes.
		return net.IPv4(raw[3], raw[2], raw[1], raw[0]), int(port), nil
	case 16:
		// Four little-endian words: reverse the bytes within each word.
		b := make([]byte, 16)
		for w := 0; w < 4; w++ {
			s := raw[w*4 : w*4+4]
			b[w*4], b[w*4+1], b[w*4+2], b[w*4+3] = s[3], s[2], s[1], s[0]
		}
		return net.IP(b), int(port), nil
	default:
		return nil, 0, fmt.Errorf("unexpected address length %d in %q", len(raw), addrHex)
	}
}

// parseProcNet parses the contents of a /proc/<pid>/net/{tcp,tcp6,udp,udp6}
// table, keeping only sockets whose inode is in ownInodes (the target
// process's sockets). proto is the label to stamp ("tcp" or "udp").
//
// TCP: LISTEN sockets become listening ports; ESTABLISHED/SYN_SENT with a
// remote become outbound connections. UDP: only connected sockets (with a
// remote) count as outbound — unconnected UDP sockets are almost always
// ephemeral client sockets on random local ports and would be pure noise.
func parseProcNet(data, proto string, ownInodes map[string]bool) ([]schema.ListeningPort, []schema.OutboundConnection) {
	var listening []schema.ListeningPort
	var outbound []schema.OutboundConnection

	for i, line := range strings.Split(data, "\n") {
		if i == 0 { // header row
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		inode := fields[9]
		if ownInodes != nil && !ownInodes[inode] {
			continue
		}
		state, err := strconv.ParseUint(fields[3], 16, 8)
		if err != nil {
			continue
		}
		localIP, localPort, err := parseHexAddr(fields[1])
		if err != nil {
			continue
		}
		remIP, remPort, err := parseHexAddr(fields[2])
		if err != nil {
			continue
		}

		if proto == "tcp" {
			switch int(state) {
			case tcpListen:
				listening = append(listening, schema.ListeningPort{
					Proto: proto, Address: localIP.String(), Port: localPort,
				})
			case tcpEstablished, tcpSynSent:
				if remPort != 0 {
					outbound = append(outbound, schema.OutboundConnection{
						Proto: proto, DestinationIP: remIP.String(), DestinationPort: remPort,
					})
				}
			}
			continue
		}

		// UDP: only connected sockets (remote set) are meaningful outbound.
		if remPort != 0 {
			outbound = append(outbound, schema.OutboundConnection{
				Proto: proto, DestinationIP: remIP.String(), DestinationPort: remPort,
			})
		}
	}
	return listening, outbound
}
