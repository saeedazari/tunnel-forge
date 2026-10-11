package main

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

// fakeSocks accepts one SOCKS5 CONNECT, records the requested destination, then runs handle.
func fakeSocks(t *testing.T, handle func(c net.Conn)) (addr string, dest chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	dest = make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		hello := make([]byte, 3)
		if _, err := io.ReadFull(c, hello); err != nil {
			return
		}
		_, _ = c.Write([]byte{5, 0})
		req := make([]byte, 10)
		if _, err := io.ReadFull(c, req); err != nil {
			return
		}
		ip := net.IPv4(req[4], req[5], req[6], req[7])
		dest <- net.JoinHostPort(ip.String(), strconv.Itoa(int(binary.BigEndian.Uint16(req[8:10]))))
		_, _ = c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
		handle(c)
	}()
	return ln.Addr().String(), dest
}

func TestSocksConnectSendsIPv4Destination(t *testing.T) {
	addr, dest := fakeSocks(t, func(c net.Conn) {
		buf := make([]byte, 4)
		if _, err := io.ReadFull(c, buf); err == nil {
			_, _ = c.Write(buf)
		}
	})
	conn, err := socksConnect(context.Background(), addr, net.ParseIP("93.184.216.34"), 443)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if got := <-dest; got != "93.184.216.34:443" {
		t.Fatalf("destination = %s", got)
	}
	_, _ = conn.Write([]byte("ping"))
	echo := make([]byte, 4)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(conn, echo); err != nil || string(echo) != "ping" {
		t.Fatalf("echo = %q err=%v", echo, err)
	}
}

func TestSocksConnectRejectsIPv6(t *testing.T) {
	if _, err := socksConnect(context.Background(), "127.0.0.1:1", net.ParseIP("2001:db8::1"), 80); err == nil {
		t.Fatal("expected IPv6 destination to be rejected")
	}
}

func TestSocksConnectReportsRefusal(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.ReadFull(c, make([]byte, 3))
		_, _ = c.Write([]byte{5, 0})
		_, _ = io.ReadFull(c, make([]byte, 10))
		_, _ = c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
	}()
	if _, err := socksConnect(context.Background(), ln.Addr().String(), net.ParseIP("10.0.0.1"), 80); err == nil {
		t.Fatal("expected refusal error")
	}
}

func TestDNSOverSocksFramesQueryAndResponse(t *testing.T) {
	query := append([]byte{0xab, 0xcd, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}, []byte("\x03www\x07example\x03com\x00\x00\x01\x00\x01")...)
	answer := []byte{0xab, 0xcd, 0x81, 0x80, 0, 1, 0, 1}
	addr, dest := fakeSocks(t, func(c net.Conn) {
		var l [2]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return
		}
		got := make([]byte, binary.BigEndian.Uint16(l[:]))
		if _, err := io.ReadFull(c, got); err != nil || string(got) != string(query) {
			return
		}
		out := make([]byte, 2+len(answer))
		binary.BigEndian.PutUint16(out, uint16(len(answer)))
		copy(out[2:], answer)
		_, _ = c.Write(out)
	})
	resp, err := dnsOverSocks(context.Background(), addr, net.ParseIP("1.1.1.1"), query)
	if err != nil {
		t.Fatal(err)
	}
	if string(resp) != string(answer) {
		t.Fatalf("response = %x", resp)
	}
	if got := <-dest; got != "1.1.1.1:53" {
		t.Fatalf("dns server = %s", got)
	}
}

func TestResolveOverSocksFallsBackToSecondServer(t *testing.T) {
	query := make([]byte, 20)
	answer := []byte{1, 2, 3, 4}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for i := 0; ; i++ {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = io.ReadFull(c, make([]byte, 3))
			_, _ = c.Write([]byte{5, 0})
			req := make([]byte, 10)
			_, _ = io.ReadFull(c, req)
			if req[4] == 9 { // first resolver 9.9.9.9 is "down"
				_, _ = c.Write([]byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0})
				c.Close()
				continue
			}
			_, _ = c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
			var l [2]byte
			_, _ = io.ReadFull(c, l[:])
			_, _ = io.ReadFull(c, make([]byte, binary.BigEndian.Uint16(l[:])))
			out := make([]byte, 2+len(answer))
			binary.BigEndian.PutUint16(out, uint16(len(answer)))
			copy(out[2:], answer)
			_, _ = c.Write(out)
			c.Close()
		}
	}()
	eng := &tunProxyEngine{socksAddr: ln.Addr().String(), dns: []string{"9.9.9.9", "1.1.1.1"}}
	resp, err := eng.resolveOverSocks(context.Background(), query)
	if err != nil || string(resp) != string(answer) {
		t.Fatalf("resp=%x err=%v", resp, err)
	}
}

func TestResolveOverSocksRejectsShortQuery(t *testing.T) {
	eng := &tunProxyEngine{socksAddr: "127.0.0.1:1", dns: []string{"1.1.1.1"}}
	if _, err := eng.resolveOverSocks(context.Background(), []byte{1, 2, 3}); err == nil {
		t.Fatal("expected short query to be rejected")
	}
}

func dnsQuery(name string, qtype uint16) []byte {
	q := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			q = append(q, byte(i-start))
			q = append(q, name[start:i]...)
			start = i + 1
		}
	}
	q = append(q, 0, byte(qtype>>8), byte(qtype), 0, 1)
	return q
}

func TestParseDNSQuestion(t *testing.T) {
	name, qtype, qclass, end, ok := parseDNSQuestion(dnsQuery("WWW.Example.com", 1))
	if !ok || name != "www.example.com" || qtype != 1 || qclass != 1 || end != len(dnsQuery("www.example.com", 1)) {
		t.Fatalf("got %q %d %d %d %v", name, qtype, qclass, end, ok)
	}
	if _, _, _, _, ok := parseDNSQuestion([]byte{1, 2, 3}); ok {
		t.Fatal("short packet accepted")
	}
	bad := dnsQuery("a.com", 1)
	bad[12] = 0xC0 // compression pointer in question
	if _, _, _, _, ok := parseDNSQuestion(bad); ok {
		t.Fatal("compressed question accepted")
	}
}

func TestAnswerDNSFakeIPForAAndEmptyForAAAA(t *testing.T) {
	eng := &tunProxyEngine{pool: newFakeIPPool()}
	resp, err := eng.answerDNS(context.Background(), dnsQuery("example.com", 1))
	if err != nil {
		t.Fatal(err)
	}
	if resp[0] != 0x12 || resp[1] != 0x34 || resp[2]&0x80 == 0 || resp[7] != 1 {
		t.Fatalf("bad A response header % x", resp[:12])
	}
	ip := net.IP(resp[len(resp)-4:])
	domain, inRange := eng.pool.lookup(ip)
	if !inRange || domain != "example.com" {
		t.Fatalf("lookup(%s) = %q %v", ip, domain, inRange)
	}
	again, _ := eng.answerDNS(context.Background(), dnsQuery("EXAMPLE.com", 1))
	if !net.IP(again[len(again)-4:]).Equal(ip) {
		t.Fatal("same domain must keep its fake address")
	}
	empty, err := eng.answerDNS(context.Background(), dnsQuery("example.com", 28))
	if err != nil || empty[7] != 0 || empty[3]&0x0f != 0 {
		t.Fatalf("AAAA must be an empty NOERROR: % x err=%v", empty, err)
	}
}

func TestFakeIPPoolRecyclesOldestAndRefusesUnknown(t *testing.T) {
	p := newFakeIPPool()
	first := p.alloc("first.test")
	for i := 1; i < fakePoolSize; i++ {
		p.alloc(strconv.Itoa(i) + ".test")
	}
	p.alloc("overflow.test") // wraps onto first's slot
	if d, _ := p.lookup(first); d != "overflow.test" {
		t.Fatalf("slot not recycled: %q", d)
	}
	if d, inRange := p.lookup(net.ParseIP("198.18.0.2")); d != "" || !inRange {
		t.Fatal("TUN block must be reserved and have no domain")
	}
	if _, inRange := p.lookup(net.ParseIP("93.184.216.34")); inRange {
		t.Fatal("public address must not be treated as fake")
	}
}

func TestSocksConnectHostSendsDomain(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.ReadFull(c, make([]byte, 3))
		_, _ = c.Write([]byte{5, 0})
		req := make([]byte, 5+len("example.com")+2)
		_, _ = io.ReadFull(c, req)
		got <- req
		_, _ = c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	}()
	conn, err := socksConnectHost(context.Background(), ln.Addr().String(), "example.com", 8443)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	req := <-got
	if req[3] != 3 || req[4] != byte(len("example.com")) || string(req[5:16]) != "example.com" || req[16] != 0x20 || req[17] != 0xfb {
		t.Fatalf("request = % x", req)
	}
}
