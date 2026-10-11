package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// These tests run the real engine against a socketpair that stands in for the Android TUN fd, so
// the promiscuous netstack, the UDP/TCP forwarders and the SOCKS5 hand-off are all exercised.

func inetChecksum(b []byte, initial uint32) uint16 {
	sum := initial
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func ipv4Packet(src, dst net.IP, proto byte, payload []byte) []byte {
	b := make([]byte, 20+len(payload))
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	b[8] = 64
	b[9] = proto
	copy(b[12:16], src.To4())
	copy(b[16:20], dst.To4())
	binary.BigEndian.PutUint16(b[10:], inetChecksum(b[:20], 0))
	copy(b[20:], payload)
	return b
}

func udpPacket(src, dst net.IP, sport, dport uint16, payload []byte) []byte {
	u := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(u[0:], sport)
	binary.BigEndian.PutUint16(u[2:], dport)
	binary.BigEndian.PutUint16(u[4:], uint16(len(u)))
	copy(u[8:], payload) // checksum 0 = unused, valid for IPv4
	return ipv4Packet(src, dst, 17, u)
}

func tcpSyn(src, dst net.IP, sport, dport uint16) []byte {
	seg := make([]byte, 20)
	binary.BigEndian.PutUint16(seg[0:], sport)
	binary.BigEndian.PutUint16(seg[2:], dport)
	binary.BigEndian.PutUint32(seg[4:], 1000)
	seg[12] = 5 << 4
	seg[13] = 0x02 // SYN
	binary.BigEndian.PutUint16(seg[14:], 65535)
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], src.To4())
	copy(pseudo[4:8], dst.To4())
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:], uint16(len(seg)))
	binary.BigEndian.PutUint16(seg[16:], inetChecksum(append(pseudo, seg...), 0))
	return ipv4Packet(src, dst, 6, seg)
}

func newTunPair(t *testing.T) *os.File {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET, 0)
	if err != nil {
		t.Skipf("socketpair unavailable: %v", err)
	}
	if err := syscall.SetNonblock(fds[1], true); err != nil {
		t.Fatal(err)
	}
	engineSide, testSide := fds[0], os.NewFile(uintptr(fds[1]), "test-tun")
	t.Cleanup(func() {
		stopTunProxyForTest()
		_ = testSide.Close()
		_ = syscall.Close(engineSide)
	})
	socksListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { socksListener.Close() })
	tunTestSocks = socksListener
	port := socksListener.Addr().(*net.TCPAddr).Port
	if rc := startTunProxy(engineSide, 1500, port, []string{"1.1.1.1"}); rc != 0 {
		t.Fatalf("startTunProxy rc=%d err=%v", rc, tunProxyLastErr.Load())
	}
	return testSide
}

var tunTestSocks net.Listener

func stopTunProxyForTest() {
	tunProxyMu.Lock()
	defer tunProxyMu.Unlock()
	stopTunProxyLocked()
}

// readPacket returns the next IPv4 packet that match accepts, or fails after a timeout.
func readPacket(t *testing.T, f *os.File, match func([]byte) bool) []byte {
	t.Helper()
	buf := make([]byte, 4096)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_ = f.SetReadDeadline(time.Now().Add(time.Second))
		n, err := f.Read(buf)
		if err != nil {
			continue
		}
		if n >= 20 && match(buf[:n]) {
			return append([]byte(nil), buf[:n]...)
		}
	}
	t.Logf("engine state: %s", engineDiagnostics())
	t.Fatal("timed out waiting for a matching packet from the engine")
	return nil
}

func TestEngineAnswersDNSWithFakeIPThenProxiesTCPByDomain(t *testing.T) {
	tun := newTunPair(t)
	client := net.ParseIP("198.18.0.1")
	dnsServer := net.ParseIP("198.18.0.2")

	// 1. DNS A query for example.com is answered locally with a fake address.
	query := dnsQuery("example.com", 1)
	if _, err := tun.Write(udpPacket(client, dnsServer, 40000, 53, query)); err != nil {
		t.Fatal(err)
	}
	reply := readPacket(t, tun, func(p []byte) bool { return p[9] == 17 && binary.BigEndian.Uint16(p[20:]) == 53 })
	payload := reply[28:]
	if len(payload) < 16 || payload[0] != 0x12 || payload[1] != 0x34 || payload[7] != 1 {
		t.Fatalf("unexpected DNS reply % x", payload)
	}
	fake := net.IP(payload[len(payload)-4:])
	if domain, ok := tunProxyCurrent.pool.lookup(fake); !ok || domain != "example.com" {
		t.Fatalf("fake address %s does not map to example.com (%q)", fake, domain)
	}

	// 2. A SYN to the fake address is accepted by the netstack and handed to SOCKS5 with the domain.
	got := make(chan string, 1)
	go func() {
		c, err := tunTestSocks.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.ReadFull(c, make([]byte, 3))
		_, _ = c.Write([]byte{5, 0})
		head := make([]byte, 5)
		if _, err := io.ReadFull(c, head); err != nil || head[3] != 3 {
			got <- "bad request"
			return
		}
		rest := make([]byte, int(head[4])+2)
		_, _ = io.ReadFull(c, rest)
		got <- string(rest[:head[4]]) + ":" + strconv.Itoa(int(binary.BigEndian.Uint16(rest[head[4]:])))
		_, _ = c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
		time.Sleep(200 * time.Millisecond)
	}()
	if _, err := tun.Write(tcpSyn(client, fake, 50000, 443)); err != nil {
		t.Fatal(err)
	}
	synAck := readPacket(t, tun, func(p []byte) bool { return p[9] == 6 && p[20+13] == 0x12 })
	if binary.BigEndian.Uint16(synAck[20:]) != 443 {
		t.Fatalf("SYN-ACK from wrong port % x", synAck[:28])
	}
	select {
	case dest := <-got:
		if dest != "example.com:443" {
			t.Fatalf("SOCKS destination = %q", dest)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("engine never contacted the SOCKS5 listener")
	}
}

func TestEngineDropsIPv6AndNonDNSUDP(t *testing.T) {
	tun := newTunPair(t)
	client := net.ParseIP("198.18.0.1")
	// A QUIC-style UDP packet and a v6 packet must produce no reply and must not crash the engine.
	_, _ = tun.Write(udpPacket(client, net.ParseIP("93.184.216.34"), 40001, 443, []byte("quic")))
	_, _ = tun.Write([]byte{0x60, 0, 0, 0, 0, 0, 59, 64})
	time.Sleep(300 * time.Millisecond)
	if tunProxyUDPDrop.Load() == 0 {
		t.Logf("engine state: %s", engineDiagnostics())
		t.Fatal("non-DNS UDP should be counted as dropped")
	}
	// The engine still answers DNS afterwards.
	if _, err := tun.Write(udpPacket(client, net.ParseIP("198.18.0.2"), 40002, 53, dnsQuery("still.works", 1))); err != nil {
		t.Fatal(err)
	}
	readPacket(t, tun, func(p []byte) bool { return p[9] == 17 && binary.BigEndian.Uint16(p[22:]) == 40002 })
}

// engineDiagnostics lists every non-zero netstack counter plus the engine counters, so a failing
// run shows where a packet was discarded.
func engineDiagnostics() string {
	out := []string{
		fmt.Sprintf("pktIn=%d pktOut=%d udpDrop=%d dnsOK=%d dnsFailed=%d", tunProxyPktIn.Load(), tunProxyPktOut.Load(), tunProxyUDPDrop.Load(), tunProxyDNSOK.Load(), tunProxyDNSFailed.Load()),
		fmt.Sprintf("lastErr=%v", tunProxyLastErr.Load()),
	}
	if eng := tunProxyCurrent; eng != nil {
		stats := eng.stack.Stats()
		walkStats(reflect.ValueOf(stats), "", &out)
	}
	return fmt.Sprintf("%v", out)
}

func walkStats(v reflect.Value, prefix string, out *[]string) {
	v = reflect.Indirect(v)
	if v.Kind() != reflect.Struct {
		return
	}
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		name := prefix + v.Type().Field(i).Name
		if f.Kind() == reflect.Ptr && !f.IsNil() {
			if m := f.MethodByName("Value"); m.IsValid() && m.Type().NumIn() == 0 {
				if n := m.Call(nil)[0]; n.Kind() == reflect.Uint64 && n.Uint() > 0 {
					*out = append(*out, fmt.Sprintf("%s=%d", name, n.Uint()))
				}
				continue
			}
		}
		if f.CanInterface() {
			walkStats(f, name+".", out)
		}
	}
}
