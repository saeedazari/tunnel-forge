package io.github.evokelektrique.tunnelforge

import android.util.Log
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.InetAddress

enum class UpstreamProxyType(val wireValue: String) {
    socks5("socks5"),
    http("http"),
    ;

    companion object {
        fun fromWire(value: String?): UpstreamProxyType =
            values().firstOrNull { it.wireValue == value } ?: socks5
    }
}

/**
 * A second proxy that every outbound TCP connection is chained through.
 *
 * The upstream is reached through the L2TP tunnel (for example a proxy that lives on the remote
 * LAN), so the destination only ever sees the upstream proxy's address.
 */
data class UpstreamProxyConfig(
    val type: UpstreamProxyType,
    val host: String,
    val port: Int,
) {
    companion object {
        /** Returns null when the feature is off or the endpoint is incomplete. */
        fun fromValues(enabled: Boolean, type: String?, host: String?, port: Int): UpstreamProxyConfig? {
            val cleanHost = host?.trim().orEmpty()
            if (!enabled || cleanHost.isEmpty() || port !in 1..65535) return null
            return UpstreamProxyConfig(UpstreamProxyType.fromWire(type), cleanHost, port)
        }
    }
}

/**
 * Wraps another [ProxyTransport] so each TCP session first connects to the upstream proxy and
 * negotiates a tunnel to the real target (SOCKS5 no-auth or HTTP CONNECT).
 *
 * UDP is rejected on purpose: forwarding it directly would bypass the upstream and leak the
 * tunnel's own address.
 */
class ChainedProxyTransport(
    private val base: ProxyTransport,
    private val upstream: UpstreamProxyConfig,
    private val logger: (Int, String) -> Unit = { _, _ -> },
) : ProxyTransport {
    override fun openTcpSession(request: ProxyConnectRequest): ProxyTransportSession {
        val inner = base.openTcpSession(ProxyConnectRequest(upstream.host, upstream.port, request.protocol))
        return ChainedProxyTransportSession(inner, request, upstream, logger)
    }

    override fun openUdpAssociation(request: ProxyConnectRequest): ProxyUdpAssociation {
        throw ProxyTransportException(
            ProxyTransportFailureReason.localServiceUnavailable,
            "UDP is not supported while an upstream proxy is enabled.",
        )
    }
}

private class ChainedProxyTransportSession(
    private val inner: ProxyTransportSession,
    private val target: ProxyConnectRequest,
    private val upstream: UpstreamProxyConfig,
    private val logger: (Int, String) -> Unit,
) : ProxyTransportSession {
    override val descriptor: ProxySessionDescriptor =
        ProxySessionDescriptor(inner.descriptor.sessionId, target, inner.descriptor.openedAtMs)

    @Volatile
    private var negotiated = false

    override fun awaitConnected(timeoutMs: Long) {
        if (negotiated) return
        val deadlineMs = System.currentTimeMillis() + timeoutMs
        try {
            inner.awaitConnected(timeoutMs)
            val io = HandshakeIo(inner, deadlineMs)
            when (upstream.type) {
                UpstreamProxyType.socks5 -> socks5Connect(io, target)
                UpstreamProxyType.http -> httpConnect(io, target)
            }
            negotiated = true
            logger(
                Log.DEBUG,
                "proxy upstream ${upstream.type.wireValue} connected sid=${descriptor.sessionId} " +
                    "via=${upstream.host}:${upstream.port} target=${target.host}:${target.port}",
            )
        } catch (e: ProxyTransportException) {
            inner.close()
            throw e
        } catch (e: IOException) {
            inner.close()
            throw ProxyTransportException(
                ProxyTransportFailureReason.upstreamConnectFailed,
                "Upstream proxy ${upstream.host}:${upstream.port}: ${e.message ?: e.javaClass.simpleName}",
                e,
            )
        }
    }

    override fun readRemoteBytes(maxLen: Int, timeoutMs: Int): ByteArray? = inner.readRemoteBytes(maxLen, timeoutMs)

    override fun writeClientBytes(bytes: ByteArray, timeoutMs: Int): Int = inner.writeClientBytes(bytes, timeoutMs)

    override fun pumpBidirectional(client: ProxyClientConnection) {
        if (!negotiated) throw IOException("Upstream proxy tunnel is not established.")
        inner.pumpBidirectional(client)
    }

    override fun close() {
        inner.close()
    }
}

/** Deadline-bounded exact reads and writes over a session's streaming API. */
internal class HandshakeIo(
    private val session: ProxyTransportSession,
    private val deadlineMs: Long,
) {
    private fun remainingMs(): Int {
        val left = deadlineMs - System.currentTimeMillis()
        if (left <= 0) {
            throw ProxyTransportException(ProxyTransportFailureReason.upstreamTimeout, "Upstream proxy handshake timed out.")
        }
        return left.coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
    }

    fun write(bytes: ByteArray) {
        session.writeClientBytes(bytes, remainingMs())
    }

    fun readExactly(count: Int): ByteArray {
        val out = ByteArray(count)
        var filled = 0
        while (filled < count) {
            val chunk = session.readRemoteBytes(count - filled, remainingMs()) ?: continue
            if (chunk.isEmpty()) throw IOException("Upstream proxy closed the connection during handshake.")
            System.arraycopy(chunk, 0, out, filled, chunk.size)
            filled += chunk.size
        }
        return out
    }

    /** Reads one byte at a time so nothing past the response header is consumed. */
    fun readUntilHeaderEnd(maxBytes: Int): ByteArray {
        val out = ByteArrayOutputStream()
        while (out.size() < maxBytes) {
            out.write(readExactly(1))
            val b = out.toByteArray()
            val n = b.size
            if (n >= 4 && b[n - 4] == '\r'.code.toByte() && b[n - 3] == '\n'.code.toByte() &&
                b[n - 2] == '\r'.code.toByte() && b[n - 1] == '\n'.code.toByte()
            ) {
                return b
            }
        }
        throw ProxyTransportException(ProxyTransportFailureReason.protocolError, "Upstream proxy response header is too large.")
    }
}

internal fun socks5Connect(io: HandshakeIo, target: ProxyConnectRequest) {
    io.write(byteArrayOf(0x05, 0x01, 0x00))
    val method = io.readExactly(2)
    if (method[0] != 0x05.toByte()) {
        throw ProxyTransportException(ProxyTransportFailureReason.protocolError, "Upstream is not a SOCKS5 proxy.")
    }
    if (method[1] != 0x00.toByte()) {
        throw ProxyTransportException(
            ProxyTransportFailureReason.protocolError,
            "Upstream SOCKS5 proxy requires authentication, which is not supported.",
        )
    }
    io.write(buildSocks5ConnectRequest(target.host, target.port))
    val head = io.readExactly(4)
    if (head[0] != 0x05.toByte()) {
        throw ProxyTransportException(ProxyTransportFailureReason.protocolError, "Malformed SOCKS5 reply from upstream.")
    }
    val reply = head[1].toInt() and 0xff
    if (reply != 0) {
        throw ProxyTransportException(
            if (reply == 0x04 || reply == 0x03) ProxyTransportFailureReason.networkUnreachable else ProxyTransportFailureReason.upstreamConnectFailed,
            "Upstream SOCKS5 refused the connection: ${socks5ReplyText(reply)}.",
        )
    }
    val tail =
        when (head[3].toInt() and 0xff) {
            0x01 -> 4 + 2
            0x04 -> 16 + 2
            0x03 -> (io.readExactly(1)[0].toInt() and 0xff) + 2
            else -> throw ProxyTransportException(ProxyTransportFailureReason.protocolError, "Malformed SOCKS5 reply from upstream.")
        }
    io.readExactly(tail)
}

internal fun buildSocks5ConnectRequest(host: String, port: Int): ByteArray {
    val out = ByteArrayOutputStream()
    out.write(byteArrayOf(0x05, 0x01, 0x00))
    val literal = host.toIpv4LiteralOrNull()
    if (literal != null) {
        out.write(0x01)
        out.write(InetAddress.getByName(literal).address)
    } else {
        val name = host.toByteArray(Charsets.US_ASCII)
        if (name.isEmpty() || name.size > 255) {
            throw ProxyTransportException(ProxyTransportFailureReason.protocolError, "Target host name is not valid for SOCKS5.")
        }
        out.write(0x03)
        out.write(name.size)
        out.write(name)
    }
    out.write((port shr 8) and 0xff)
    out.write(port and 0xff)
    return out.toByteArray()
}

private fun socks5ReplyText(code: Int): String =
    when (code) {
        0x01 -> "general failure"
        0x02 -> "not allowed by ruleset"
        0x03 -> "network unreachable"
        0x04 -> "host unreachable"
        0x05 -> "connection refused"
        0x06 -> "TTL expired"
        0x07 -> "command not supported"
        0x08 -> "address type not supported"
        else -> "code $code"
    }

internal fun httpConnect(io: HandshakeIo, target: ProxyConnectRequest) {
    val authority = "${target.host}:${target.port}"
    io.write("CONNECT $authority HTTP/1.1\r\nHost: $authority\r\nProxy-Connection: keep-alive\r\n\r\n".toByteArray(Charsets.US_ASCII))
    val header = String(io.readUntilHeaderEnd(MAX_HTTP_CONNECT_HEADER_BYTES), Charsets.ISO_8859_1)
    val statusLine = header.substringBefore("\r\n")
    val status = statusLine.split(' ').getOrNull(1)?.toIntOrNull()
    if (!statusLine.startsWith("HTTP/") || status == null) {
        throw ProxyTransportException(ProxyTransportFailureReason.protocolError, "Upstream is not an HTTP proxy.")
    }
    if (status !in 200..299) {
        throw ProxyTransportException(
            ProxyTransportFailureReason.upstreamConnectFailed,
            "Upstream HTTP proxy refused CONNECT: $statusLine",
        )
    }
}

private const val MAX_HTTP_CONNECT_HEADER_BYTES = 8192
