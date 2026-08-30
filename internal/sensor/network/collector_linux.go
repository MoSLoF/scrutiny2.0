//go:build linux

package network

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/MoSLoF/scrutiny2.0/internal/schema"
)

const pollInterval = 250 * time.Millisecond

// Collect polls the target PID's socket tables for the given duration and
// returns the union of listening ports and outbound connections observed —
// a socket seen at any poll is recorded once, stamped with when it first
// appeared. Short-lived connections between polls can be missed; that is the
// accepted trade-off of a poll-based sensor versus an eBPF socket tracer.
func Collect(pid int, duration time.Duration) (*schema.NetworkObservation, error) {
	start := time.Now()
	listenSeen := map[string]schema.ListeningPort{}
	outSeen := map[string]schema.OutboundConnection{}
	rawSeen := map[string]schema.RawSocket{}
	promiscSeen := map[string]bool{}

	poll := func() {
		inodes, err := socketInodes(pid)
		if err != nil {
			return // process gone, or fd dir not readable — skip this tick
		}
		offset := time.Since(start).Milliseconds()
		for _, src := range []struct{ file, proto string }{
			{"tcp", "tcp"}, {"tcp6", "tcp"}, {"udp", "udp"}, {"udp6", "udp"},
		} {
			data, err := os.ReadFile(fmt.Sprintf("/proc/%d/net/%s", pid, src.file))
			if err != nil {
				continue
			}
			listening, outbound := parseProcNet(string(data), src.proto, inodes)
			for _, lp := range listening {
				k := lp.Proto + "|" + lp.Address + "|" + strconv.Itoa(lp.Port)
				if _, ok := listenSeen[k]; !ok {
					lp.FirstSeenOffsetMS = offset
					listenSeen[k] = lp
				}
			}
			for _, oc := range outbound {
				k := oc.Proto + "|" + oc.DestinationIP + "|" + strconv.Itoa(oc.DestinationPort)
				if _, ok := outSeen[k]; !ok {
					oc.FirstSeenOffsetMS = offset
					outSeen[k] = oc
				}
			}
		}

		// Raw and packet sockets never show up in the tcp/udp tables above —
		// this is exactly the blind spot a promiscuous-capture, no-C2
		// listener (SLEEPWALKER's technique) is designed to sit in.
		for _, src := range []struct {
			file   string
			packet bool
		}{
			{"raw", false}, {"raw6", false}, {"packet", true},
		} {
			data, err := os.ReadFile(fmt.Sprintf("/proc/%d/net/%s", pid, src.file))
			if err != nil {
				continue
			}
			var found []schema.RawSocket
			if src.packet {
				found = parsePacketSockets(string(data), inodes)
			} else {
				found = parseRawSockets(string(data), inodes)
			}
			for _, rs := range found {
				k := rs.Family + "|" + rs.Protocol + "|" + rs.Interface + "|" + rs.Inode
				if _, ok := rawSeen[k]; !ok {
					rs.FirstSeenOffsetMS = offset
					rawSeen[k] = rs
				}
			}
		}

		for _, ifname := range promiscuousInterfacesNow() {
			promiscSeen[ifname] = true
		}
	}

	poll() // sample immediately so very short runs still capture something
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	deadline := time.After(duration)
	for {
		select {
		case <-deadline:
			return finalize(listenSeen, outSeen, rawSeen, promiscSeen), nil
		case <-ticker.C:
			poll()
		}
	}
}

// promiscuousInterfacesNow reads IFF_PROMISC (0x100) off every interface's
// /sys/class/net/<if>/flags. This is SYSTEM-WIDE state — the kernel tracks
// promiscuous mode per interface, not per socket or per process — so it
// cannot on its own be attributed to the observed PID. It is reported as
// corroborating context; see the doc comment on
// schema.NetworkObservation.PromiscuousInterfaces and diffNetwork's
// handling for how it's meant to be read alongside RawSockets.
func promiscuousInterfacesNow() []string {
	const iffPromisc = 0x100
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		raw, err := os.ReadFile(fmt.Sprintf("/sys/class/net/%s/flags", e.Name()))
		if err != nil {
			continue
		}
		val := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(raw)), "0x"))
		flags, err := strconv.ParseInt(val, 16, 64)
		if err != nil {
			continue
		}
		if flags&iffPromisc != 0 {
			out = append(out, e.Name())
		}
	}
	return out
}

// socketInodes returns the set of socket inodes owned by pid, read from its
// /proc/<pid>/fd symlinks (each socket fd links to "socket:[<inode>]"). This
// is what attributes the shared per-namespace socket tables to this process.
func socketInodes(pid int) (map[string]bool, error) {
	fdDir := fmt.Sprintf("/proc/%d/fd", pid)
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return nil, err
	}
	inodes := make(map[string]bool)
	for _, e := range entries {
		link, err := os.Readlink(filepath.Join(fdDir, e.Name()))
		if err != nil {
			continue
		}
		if strings.HasPrefix(link, "socket:[") && strings.HasSuffix(link, "]") {
			inodes[link[len("socket:["):len(link)-1]] = true
		}
	}
	return inodes, nil
}

func finalize(listenSeen map[string]schema.ListeningPort, outSeen map[string]schema.OutboundConnection,
	rawSeen map[string]schema.RawSocket, promiscSeen map[string]bool) *schema.NetworkObservation {
	obs := &schema.NetworkObservation{}
	for _, v := range listenSeen {
		obs.ListeningPorts = append(obs.ListeningPorts, v)
	}
	for _, v := range outSeen {
		obs.OutboundConnections = append(obs.OutboundConnections, v)
	}
	for _, v := range rawSeen {
		obs.RawSockets = append(obs.RawSockets, v)
	}
	for ifname := range promiscSeen {
		obs.PromiscuousInterfaces = append(obs.PromiscuousInterfaces, ifname)
	}
	sort.Slice(obs.ListeningPorts, func(i, j int) bool {
		a, b := obs.ListeningPorts[i], obs.ListeningPorts[j]
		if a.Proto != b.Proto {
			return a.Proto < b.Proto
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		return a.Address < b.Address
	})
	sort.Slice(obs.OutboundConnections, func(i, j int) bool {
		a, b := obs.OutboundConnections[i], obs.OutboundConnections[j]
		if a.Proto != b.Proto {
			return a.Proto < b.Proto
		}
		if a.DestinationIP != b.DestinationIP {
			return a.DestinationIP < b.DestinationIP
		}
		return a.DestinationPort < b.DestinationPort
	})
	sort.Slice(obs.RawSockets, func(i, j int) bool {
		a, b := obs.RawSockets[i], obs.RawSockets[j]
		if a.Family != b.Family {
			return a.Family < b.Family
		}
		if a.Protocol != b.Protocol {
			return a.Protocol < b.Protocol
		}
		return a.Interface < b.Interface
	})
	sort.Strings(obs.PromiscuousInterfaces)
	return obs
}
