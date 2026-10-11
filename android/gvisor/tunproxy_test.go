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
