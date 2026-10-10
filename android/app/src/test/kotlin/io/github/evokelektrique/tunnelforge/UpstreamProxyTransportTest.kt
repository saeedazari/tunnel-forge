package io.github.evokelektrique.tunnelforge

import java.io.IOException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class UpstreamProxyTransportTest {
    private val target = ProxyConnectRequest("example.com", 443, "tcp")

    /** Scripted session: records writes, replays [replies] one chunk per read. */
    private class FakeSession(replies: List<ByteArray>) : ProxyTransportSession {
        val writes = mutableListOf<ByteArray>()
        private val queue = ArrayDeque(replies)
        var closed = false
        override val descriptor = ProxySessionDescriptor(1, ProxyConnectRequest("192.168.50.51", 18888, "tcp"), 0L)

        override fun awaitConnected(timeoutMs: Long) {}

        override fun readRemoteBytes(maxLen: Int, timeoutMs: Int): ByteArray? {
            val head = queue.removeFirstOrNull() ?: return ByteArray(0)
            if (head.size <= maxLen) return head
            queue.addFirst(head.copyOfRange(maxLen, head.size))
            return head.copyOfRange(0, maxLen)
        }

        override fun writeClientBytes(bytes: ByteArray, timeoutMs: Int): Int {
            writes += bytes
            return bytes.size
        }

        override fun pumpBidirectional(client: ProxyClientConnection) {}

        override fun close() {
            closed = true
        }
    }

    private class FakeTransport(val session: FakeSession) : ProxyTransport {
        var lastRequest: ProxyConnectRequest? = null

        override fun openTcpSession(request: ProxyConnectRequest): ProxyTransportSession {
            lastRequest = request
            return session
        }
    }

    private fun bytes(vararg v: Int) = ByteArray(v.size) { v[it].toByte() }

    @Test
    fun socks5ChainsToDomainTargetThroughUpstreamEndpoint() {
        val session = FakeSession(listOf(bytes(5, 0), bytes(5, 0, 0, 1, 1, 2, 3, 4, 0, 80)))
        val base = FakeTransport(session)
        val chained = ChainedProxyTransport(base, UpstreamProxyConfig(UpstreamProxyType.socks5, "192.168.50.51", 18888))

        chained.openTcpSession(target).awaitConnected(5_000)

        assertEquals(ProxyConnectRequest("192.168.50.51", 18888, "tcp"), base.lastRequest)
        assertArrayEquals(bytes(5, 1, 0), session.writes[0])
        val expected = bytes(5, 1, 0, 3, 11) + "example.com".toByteArray() + bytes(0x01, 0xBB)
        assertArrayEquals(expected, session.writes[1])
    }

    @Test
    fun socks5SendsIpv4LiteralAsAddressType1() {
        val request = buildSocks5ConnectRequest("10.1.2.3", 8080)
        assertArrayEquals(bytes(5, 1, 0, 1, 10, 1, 2, 3, 0x1F, 0x90), request)
    }

    @Test
    fun socks5ConnectionRefusedIsReported() {
        val session = FakeSession(listOf(bytes(5, 0), bytes(5, 5, 0, 1, 0, 0, 0, 0, 0, 0)))
        val chained = ChainedProxyTransport(FakeTransport(session), UpstreamProxyConfig(UpstreamProxyType.socks5, "h", 1))
        try {
            chained.openTcpSession(target).awaitConnected(5_000)
            fail("expected failure")
        } catch (e: ProxyTransportException) {
            assertTrue(e.message!!.contains("connection refused"))
            assertTrue(session.closed)
        }
    }

    @Test
    fun socks5AuthRequiredIsRejected() {
        val session = FakeSession(listOf(bytes(5, 2)))
        val chained = ChainedProxyTransport(FakeTransport(session), UpstreamProxyConfig(UpstreamProxyType.socks5, "h", 1))
        try {
            chained.openTcpSession(target).awaitConnected(5_000)
            fail("expected failure")
        } catch (e: ProxyTransportException) {
            assertTrue(e.message!!.contains("authentication"))
        }
    }

    @Test
    fun httpConnectSucceedsOn200AndDoesNotOverRead() {
        val session = FakeSession(listOf("HTTP/1.1 200 Connection established\r\nVia: x\r\n\r\nPAYLOAD".toByteArray()))
        val chained = ChainedProxyTransport(FakeTransport(session), UpstreamProxyConfig(UpstreamProxyType.http, "h", 1))

        val tunnel = chained.openTcpSession(target)
        tunnel.awaitConnected(5_000)

        assertTrue(String(session.writes[0]).startsWith("CONNECT example.com:443 HTTP/1.1\r\n"))
        // Bytes after the header belong to the tunneled stream and must stay unread.
        assertArrayEquals("PAYLOAD".toByteArray(), tunnel.readRemoteBytes(64, 100))
    }

    @Test
    fun httpConnectNon2xxFails() {
        val session = FakeSession(listOf("HTTP/1.1 403 Forbidden\r\n\r\n".toByteArray()))
        val chained = ChainedProxyTransport(FakeTransport(session), UpstreamProxyConfig(UpstreamProxyType.http, "h", 1))
        try {
            chained.openTcpSession(target).awaitConnected(5_000)
            fail("expected failure")
        } catch (e: ProxyTransportException) {
            assertTrue(e.message!!.contains("403"))
        }
    }

    @Test
    fun udpIsRejectedInsteadOfLeakingAround() {
        val chained = ChainedProxyTransport(
            FakeTransport(FakeSession(emptyList())),
            UpstreamProxyConfig(UpstreamProxyType.socks5, "h", 1),
        )
        try {
            chained.openUdpAssociation(target)
            fail("expected failure")
        } catch (e: IOException) {
            assertTrue(e is ProxyTransportException)
        }
    }

    @Test
    fun configRequiresEnabledHostAndPort() {
        assertNull(UpstreamProxyConfig.fromValues(false, "socks5", "h", 1))
        assertNull(UpstreamProxyConfig.fromValues(true, "socks5", " ", 1))
        assertNull(UpstreamProxyConfig.fromValues(true, "socks5", "h", 0))
        val ok = UpstreamProxyConfig.fromValues(true, "http", " 192.168.50.51 ", 18888)
        assertNotNull(ok)
        assertEquals(UpstreamProxyConfig(UpstreamProxyType.http, "192.168.50.51", 18888), ok)
    }
}
