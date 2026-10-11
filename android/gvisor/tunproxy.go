package main

import "C"

// Whole-device capture for proxy-only mode.
//
// The Android TUN fd (from TunProxyService) is attached to its own gVisor netstack that accepts
// every TCP flow regardless of destination. Each accepted flow is forwarded to the local SOCKS5
// listener (which is chained to the upstream proxy through the L2TP tunnel), so the apps on the
// phone never need to know about the proxy. DNS uses fake IPs: an A query is answered with an address
// from a private pool, and when the app connects to that address the original host name is handed to
// the SOCKS5 listener, so the upstream proxy does the real resolution (nothing resolves locally).
// AAAA and other record types get an empty answer. All other UDP and all IPv6 is dropped on
// purpose: letting it escape would leak the real address.

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const tunProxyNIC tcpip.NICID = 1

const (
	tunProxySocksDial    = 10 * time.Second
	tunProxyDNSTimeout   = 6 * time.Second
	tunProxyDNSIdle      = 4 * time.Second
	tunProxyMaxInFlight  = 4096
	tunProxyCopyBufBytes = 16 * 1024
)

// Fake-IP pool: 198.18.1.0 - 198.18.255.255. 198.18.0.0/24 is reserved for the TUN itself.
const (
	fakePoolBase = uint32(198)<<24 | uint32(18)<<16 | 1<<8
	fakePoolSize = 255 * 256
)

type fakeIPPool struct {
	mu       sync.Mutex
	byDomain map[string]int
	domains  []string
	next     int
}

func newFakeIPPool() *fakeIPPool {
	return &fakeIPPool{byDomain: make(map[string]int), domains: make([]string, fakePoolSize)}
}

func fakeIPFromIndex(i int) net.IP {
	v := fakePoolBase + uint32(i)
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// alloc returns a stable fake address for domain, recycling the oldest slot when the pool wraps.
func (p *fakeIPPool) alloc(domain string) net.IP {
	p.mu.Lock()
	defer p.mu.Unlock()
	if i, ok := p.byDomain[domain]; ok {
		return fakeIPFromIndex(i)
	}
	i := p.next
	p.next = (p.next + 1) % fakePoolSize
	if old := p.domains[i]; old != "" {
		delete(p.byDomain, old)
	}
	p.domains[i] = domain
	p.byDomain[domain] = i
	return fakeIPFromIndex(i)
}

// lookup maps a fake address back to its domain. inRange reports whether ip belongs to the
// reserved 198.18.0.0/15 block at all (so stale fake addresses can be refused instead of proxied).
func (p *fakeIPPool) lookup(ip net.IP) (domain string, inRange bool) {
	v4 := ip.To4()
	if v4 == nil || v4[0] != 198 || (v4[1] != 18 && v4[1] != 19) {
		return "", false
	}
	v := uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3])
	if v < fakePoolBase || v-fakePoolBase >= fakePoolSize {
		return "", true
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.domains[v-fakePoolBase], true
}

type tunProxyEngine struct {
	pool      *fakeIPPool
	cancel    context.CancelFunc
	stack     *stack.Stack
	linkEP    *channel.Endpoint
	tun       *os.File
	socksAddr string
	dns       []string
	wg        sync.WaitGroup
}

var (
	tunProxyMu      sync.Mutex
	tunProxyCurrent *tunProxyEngine
	tunProxyLastErr atomic.Value // string

	tunProxyActiveTCP atomic.Int64
	tunProxyTotalTCP  atomic.Uint64
	tunProxyTCPFailed atomic.Uint64
	tunProxyDNSOK     atomic.Uint64
	tunProxyDNSFailed atomic.Uint64
	tunProxyUDPDrop   atomic.Uint64
	tunProxyPktIn     atomic.Uint64
	tunProxyPktOut    atomic.Uint64

	tunProxyBufPool = sync.Pool{New: func() any { b := make([]byte, tunProxyCopyBufBytes); return &b }}
)

func tunProxyFail(format string, args ...any) {
	tunProxyLastErr.Store(fmt.Sprintf(format, args...))
}

//export tf_tunproxy_start
func tf_tunproxy_start(tunFd C.int, mtu C.int, socksPort C.int, dnsIPv4 unsafe.Pointer) C.int {
	dnsRaw := bytesFromPtr(dnsIPv4, 8)
	if tunFd < 0 || mtu < 576 || mtu > 9000 || socksPort <= 0 || socksPort > 65535 || len(dnsRaw) != 8 {
		return -1
	}
	var dns []string
	for i := 0; i < 2; i++ {
		ip := net.IPv4(dnsRaw[i*4], dnsRaw[i*4+1], dnsRaw[i*4+2], dnsRaw[i*4+3])
		if !ip.IsUnspecified() {
			dns = append(dns, ip.String())
		}
	}
	if len(dns) == 0 {
		return -1
	}

	tunProxyMu.Lock()
	defer tunProxyMu.Unlock()
	if tunProxyCurrent != nil {
		stopTunProxyLocked()
	}
	tunProxyLastErr.Store("")
	for _, c := range []interface{ Store(uint64) }{&tunProxyTotalTCP, &tunProxyTCPFailed, &tunProxyDNSOK, &tunProxyDNSFailed, &tunProxyUDPDrop, &tunProxyPktIn, &tunProxyPktOut} {
		c.Store(0)
	}
	tunProxyActiveTCP.Store(0)

	// The Java side keeps its own descriptor; this duplicate is closed independently on stop.
	dupFd, err := syscall.Dup(int(tunFd))
	if err != nil {
		tunProxyFail("dup tun fd: %v", err)
		return -2
	}
	if err := syscall.SetNonblock(dupFd, true); err != nil {
		_ = syscall.Close(dupFd)
		tunProxyFail("set nonblock: %v", err)
		return -2
	}
	tun := os.NewFile(uintptr(dupFd), "tun")

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
		HandleLocal:        true,
	})
	linkEP := channel.New(1024, uint32(mtu), "")
	if terr := s.CreateNIC(tunProxyNIC, linkEP); terr != nil {
		_ = tun.Close()
		tunProxyFail("create nic: %v", terr)
		return -3
	}
	// Accept packets for any address and answer as that address.
	if terr := s.SetPromiscuousMode(tunProxyNIC, true); terr != nil {
		_ = tun.Close()
		tunProxyFail("promiscuous: %v", terr)
		return -3
	}
	if terr := s.SetSpoofing(tunProxyNIC, true); terr != nil {
		_ = tun.Close()
		tunProxyFail("spoofing: %v", terr)
		return -3
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: tunProxyNIC}})
	sack := tcpip.TCPSACKEnabled(true)
	_ = s.SetTransportProtocolOption(tcp.ProtocolNumber, &sack)

	ctx, cancel := context.WithCancel(context.Background())
	eng := &tunProxyEngine{
		cancel:    cancel,
		stack:     s,
		linkEP:    linkEP,
		tun:       tun,
		socksAddr: fmt.Sprintf("127.0.0.1:%d", int(socksPort)),
		dns:       dns,
		pool:      newFakeIPPool(),
	}

	tcpFwd := tcp.NewForwarder(s, 0, tunProxyMaxInFlight, func(r *tcp.ForwarderRequest) {
		id := r.ID()
		var wq waiter.Queue
		ep, terr := r.CreateEndpoint(&wq)
		if terr != nil {
			r.Complete(true)
			return
		}
		r.Complete(false)
		conn := gonet.NewTCPConn(&wq, ep)
		dst := id.LocalAddress.As4()
		eng.wg.Add(1)
		go func() {
			defer eng.wg.Done()
			eng.serveTCP(ctx, conn, net.IPv4(dst[0], dst[1], dst[2], dst[3]), id.LocalPort)
		}()
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)

	udpFwd := udp.NewForwarder(s, func(r *udp.ForwarderRequest) {
		id := r.ID()
		if id.LocalPort != 53 {
			tunProxyUDPDrop.Add(1)
			return
		}
		var wq waiter.Queue
		ep, terr := r.CreateEndpoint(&wq)
		if terr != nil {
			tunProxyDNSFailed.Add(1)
			return
		}
		conn := gonet.NewUDPConn(&wq, ep)
		eng.wg.Add(1)
		go func() {
			defer eng.wg.Done()
			eng.serveDNS(ctx, conn)
		}()
	})
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	eng.wg.Add(2)
	go func() {
		defer eng.wg.Done()
		eng.pumpTunToStack(ctx, int(mtu))
	}()
	go func() {
		defer eng.wg.Done()
		eng.pumpStackToTun(ctx)
	}()

	tunProxyCurrent = eng
	return 0
}

func stopTunProxyLocked() {
	eng := tunProxyCurrent
	tunProxyCurrent = nil
	if eng == nil {
		return
	}
	eng.cancel()
	_ = eng.tun.Close()
	eng.linkEP.Close()
	eng.stack.Close()
	done := make(chan struct{})
	go func() { eng.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
	}
}

//export tf_tunproxy_stop
func tf_tunproxy_stop() {
	tunProxyMu.Lock()
	defer tunProxyMu.Unlock()
	stopTunProxyLocked()
}

//export tf_tunproxy_stats
func tf_tunproxy_stats(out unsafe.Pointer, count C.int) C.int {
	if out == nil || count < 9 {
		return -1
	}
	tunProxyMu.Lock()
	running := tunProxyCurrent != nil
	tunProxyMu.Unlock()
	stats := unsafe.Slice((*C.int)(out), int(count))
	// Positional ABI: keep aligned with Kotlin formatTunProxyStats.
	stats[0] = boolInt(running)
	stats[1] = C.int(tunProxyActiveTCP.Load())
	stats[2] = C.int(tunProxyTotalTCP.Load())
	stats[3] = C.int(tunProxyTCPFailed.Load())
	stats[4] = C.int(tunProxyDNSOK.Load())
	stats[5] = C.int(tunProxyDNSFailed.Load())
	stats[6] = C.int(tunProxyUDPDrop.Load())
	stats[7] = C.int(tunProxyPktIn.Load())
	stats[8] = C.int(tunProxyPktOut.Load())
	return 9
}

//export tf_tunproxy_last_error
func tf_tunproxy_last_error(out unsafe.Pointer, count C.int) C.int {
	if out == nil || count <= 0 {
		return -1
	}
	msg, _ := tunProxyLastErr.Load().(string)
	buf := unsafe.Slice((*byte)(out), int(count))
	n := copy(buf, []byte(msg))
	if n >= len(buf) {
		n = len(buf) - 1
	}
	buf[n] = 0
	return C.int(n)
}

func (e *tunProxyEngine) pumpTunToStack(ctx context.Context, mtu int) {
	buf := make([]byte, mtu+64)
	for ctx.Err() == nil {
		n, err := e.tun.Read(buf)
		if err != nil {
			if ctx.Err() == nil {
				tunProxyFail("tun read: %v", err)
			}
			return
		}
		if n < 20 || buf[0]>>4 != 4 {
			// IPv6 and anything malformed is dropped so it cannot bypass the proxy.
			continue
		}
		data := make([]byte, n)
		copy(data, buf[:n])
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(data)})
		e.linkEP.InjectInbound(ipv4.ProtocolNumber, pkt)
		pkt.DecRef()
		tunProxyPktIn.Add(1)
	}
}

func (e *tunProxyEngine) pumpStackToTun(ctx context.Context) {
	for ctx.Err() == nil {
		pkt := e.linkEP.ReadContext(ctx)
		if pkt == nil {
			return
		}
		data := pkt.ToBuffer()
		flat := data.Flatten()
		pkt.DecRef()
		if _, err := e.tun.Write(flat); err != nil {
			if ctx.Err() == nil {
				tunProxyFail("tun write: %v", err)
			}
			return
		}
		tunProxyPktOut.Add(1)
	}
}

func (e *tunProxyEngine) serveTCP(ctx context.Context, client *gonet.TCPConn, dst net.IP, dport uint16) {
	tunProxyActiveTCP.Add(1)
	tunProxyTotalTCP.Add(1)
	defer tunProxyActiveTCP.Add(-1)
	defer client.Close()

	var remote net.Conn
	var err error
	if domain, inRange := e.pool.lookup(dst); inRange {
		if domain == "" {
			// Reserved block with no name behind it (TUN address, stale fake IP): refuse quickly.
			tunProxyTCPFailed.Add(1)
			return
		}
		remote, err = socksConnectHost(ctx, e.socksAddr, domain, dport)
	} else {
		remote, err = socksConnect(ctx, e.socksAddr, dst, dport)
	}
	if err != nil {
		tunProxyTCPFailed.Add(1)
		tunProxyFail("tcp %s:%d: %v", dst, dport, err)
		return
	}
	defer remote.Close()

	done := make(chan struct{}, 2)
	relay := func(dstConn, srcConn net.Conn) {
		bufp := tunProxyBufPool.Get().(*[]byte)
		_, _ = io.CopyBuffer(dstConn, srcConn, *bufp)
		tunProxyBufPool.Put(bufp)
		if cw, ok := dstConn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}
	go relay(remote, client)
	go relay(client, remote)
	select {
	case <-done:
		// One direction finished; give the other a bounded time to drain, then tear down.
		select {
		case <-done:
		case <-time.After(30 * time.Second):
		case <-ctx.Done():
		}
	case <-ctx.Done():
	}
}

func (e *tunProxyEngine) serveDNS(ctx context.Context, conn *gonet.UDPConn) {
	defer conn.Close()
	buf := make([]byte, 4096)
	for ctx.Err() == nil {
		_ = conn.SetReadDeadline(time.Now().Add(tunProxyDNSIdle))
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			return
		}
		resp, err := e.answerDNS(ctx, buf[:n])
		if err != nil {
			tunProxyDNSFailed.Add(1)
			tunProxyFail("dns: %v", err)
			continue
		}
		tunProxyDNSOK.Add(1)
		if _, err := conn.Write(resp); err != nil {
			return
		}
	}
}

const (
	dnsTypeA     = 1
	dnsTypeNS    = 2
	dnsTypeMX    = 15
	dnsTypeTXT   = 16
	dnsTypeSRV   = 33
	dnsClassIN   = 1
	fakeIPTTLSec = 60
)

// answerDNS replies to A queries with a fake address and to most other types with an empty
// NOERROR answer. Record types that carry no addresses (MX/TXT/SRV/NS) are resolved for real over
// the SOCKS5 listener so mail and service lookups keep working.
func (e *tunProxyEngine) answerDNS(ctx context.Context, query []byte) ([]byte, error) {
	name, qtype, qclass, qEnd, ok := parseDNSQuestion(query)
	if !ok {
		return nil, errors.New("unsupported dns query")
	}
	if qclass == dnsClassIN && qtype == dnsTypeA {
		return buildDNSResponse(query, qEnd, e.pool.alloc(name)), nil
	}
	switch qtype {
	case dnsTypeMX, dnsTypeTXT, dnsTypeSRV, dnsTypeNS:
		return e.resolveOverSocks(ctx, query)
	}
	return buildDNSResponse(query, qEnd, nil), nil
}

// parseDNSQuestion reads the single question of a standard query. Compression pointers are not
// valid in the question of a query, so they are rejected.
func parseDNSQuestion(q []byte) (name string, qtype, qclass uint16, qEnd int, ok bool) {
	if len(q) < 12 || q[2]&0x80 != 0 || binary.BigEndian.Uint16(q[4:6]) != 1 {
		return
	}
	pos := 12
	var labels []byte
	for {
		if pos >= len(q) {
			return
		}
		l := int(q[pos])
		if l == 0 {
			pos++
			break
		}
		if l&0xC0 != 0 || pos+1+l > len(q) {
			return
		}
		if len(labels) > 0 {
			labels = append(labels, '.')
		}
		for _, c := range q[pos+1 : pos+1+l] {
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			labels = append(labels, c)
		}
		pos += 1 + l
		if len(labels) > 253 {
			return
		}
	}
	if pos+4 > len(q) || len(labels) == 0 {
		return
	}
	return string(labels), binary.BigEndian.Uint16(q[pos : pos+2]), binary.BigEndian.Uint16(q[pos+2 : pos+4]), pos + 4, true
}

// buildDNSResponse echoes the question and adds one A record for ip, or none when ip is nil.
func buildDNSResponse(q []byte, qEnd int, ip net.IP) []byte {
	resp := make([]byte, 0, qEnd+16)
	resp = append(resp, q[0], q[1], 0x80|(q[2]&0x78)|(q[2]&0x01), 0x80)
	answers := byte(0)
	if ip != nil {
		answers = 1
	}
	resp = append(resp, 0, 1, 0, answers, 0, 0, 0, 0)
	resp = append(resp, q[12:qEnd]...)
	if ip != nil {
		v4 := ip.To4()
		resp = append(resp, 0xC0, 0x0C, 0, dnsTypeA, 0, dnsClassIN, 0, 0, 0, fakeIPTTLSec, 0, 4, v4[0], v4[1], v4[2], v4[3])
	}
	return resp
}

// resolveOverSocks forwards one DNS query to the configured resolvers over TCP via the local
// SOCKS5 listener, so name lookups leave through the upstream proxy like everything else.
func (e *tunProxyEngine) resolveOverSocks(ctx context.Context, query []byte) ([]byte, error) {
	if len(query) < 12 || len(query) > 65535 {
		return nil, errors.New("bad dns query")
	}
	var lastErr error
	for _, server := range e.dns {
		resp, err := dnsOverSocks(ctx, e.socksAddr, net.ParseIP(server), query)
		if err == nil {
			return resp, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func dnsOverSocks(ctx context.Context, socksAddr string, server net.IP, query []byte) ([]byte, error) {
	c, err := socksConnect(ctx, socksAddr, server, 53)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(tunProxyDNSTimeout))
	framed := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(framed, uint16(len(query)))
	copy(framed[2:], query)
	if _, err := c.Write(framed); err != nil {
		return nil, err
	}
	var lenBuf [2]byte
	if _, err := io.ReadFull(c, lenBuf[:]); err != nil {
		return nil, err
	}
	resp := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
	if _, err := io.ReadFull(c, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// socksConnect opens a SOCKS5 (no-auth) CONNECT to an IPv4 destination through socksAddr.
func socksConnect(ctx context.Context, socksAddr string, dst net.IP, dport uint16) (net.Conn, error) {
	ip4 := dst.To4()
	if ip4 == nil {
		return nil, errors.New("only IPv4 destinations are supported")
	}
	return socksConnectRaw(ctx, socksAddr, append([]byte{1}, ip4...), dport)
}

// socksConnectHost sends the host name itself so the upstream proxy resolves it.
func socksConnectHost(ctx context.Context, socksAddr string, host string, dport uint16) (net.Conn, error) {
	if len(host) == 0 || len(host) > 255 {
		return nil, errors.New("invalid host name")
	}
	return socksConnectRaw(ctx, socksAddr, append([]byte{3, byte(len(host))}, host...), dport)
}

// socksConnectRaw performs the handshake; addr is ATYP followed by the address bytes.
func socksConnectRaw(ctx context.Context, socksAddr string, addr []byte, dport uint16) (net.Conn, error) {
	d := net.Dialer{Timeout: tunProxySocksDial}
	c, err := d.DialContext(ctx, "tcp", socksAddr)
	if err != nil {
		return nil, err
	}
	_ = c.SetDeadline(time.Now().Add(tunProxySocksDial + 20*time.Second))
	fail := func(err error) (net.Conn, error) {
		_ = c.Close()
		return nil, err
	}
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		return fail(err)
	}
	var method [2]byte
	if _, err := io.ReadFull(c, method[:]); err != nil {
		return fail(err)
	}
	if method[0] != 5 || method[1] != 0 {
		return fail(errors.New("socks5 handshake rejected"))
	}
	req := append([]byte{5, 1, 0}, addr...)
	req = append(req, byte(dport>>8), byte(dport))
	if _, err := c.Write(req); err != nil {
		return fail(err)
	}
	var head [4]byte
	if _, err := io.ReadFull(c, head[:]); err != nil {
		return fail(err)
	}
	if head[0] != 5 || head[1] != 0 {
		return fail(fmt.Errorf("socks5 connect refused (code %d)", head[1]))
	}
	var rest int
	switch head[3] {
	case 1:
		rest = 4 + 2
	case 4:
		rest = 16 + 2
	case 3:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return fail(err)
		}
		rest = int(l[0]) + 2
	default:
		return fail(errors.New("malformed socks5 reply"))
	}
	if _, err := io.CopyN(io.Discard, c, int64(rest)); err != nil {
		return fail(err)
	}
	_ = c.SetDeadline(time.Time{})
	return c, nil
}
