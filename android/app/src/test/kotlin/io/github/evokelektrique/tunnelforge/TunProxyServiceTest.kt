package io.github.evokelektrique.tunnelforge

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

class TunProxyServiceTest {
    private fun dns(host: String) = DnsServerConfig(host = host, protocol = DnsProtocol.dnsOverUdp)

    @Test
    fun defaultsToPublicResolversWhenProfileHasNone() {
        assertArrayEquals(TunProxyService.DEFAULT_DNS_IPV4, TunProxyService.dnsIpv4For(emptyList()))
    }

    @Test
    fun usesLiteralIpv4ResolversFromProfileOnly() {
        val out = TunProxyService.dnsIpv4For(listOf(dns("dns.example.com"), dns("9.9.9.9"), dns("149.112.112.112")))
        assertArrayEquals(intArrayOf(9, 9, 9, 9, 149, 112, 112, 112), out)
    }

    @Test
    fun singleResolverLeavesSecondSlotEmpty() {
        val out = TunProxyService.dnsIpv4For(listOf(dns("10.0.0.53")))
        assertArrayEquals(intArrayOf(10, 0, 0, 53, 0, 0, 0, 0), out)
        assertEquals("10.0.0.53", TunProxyService.formatDns(out))
    }

    @Test
    fun statsFormatKeepsPositionalOrder() {
        val text = TunProxyService.formatTunProxyStats(intArrayOf(1, 2, 3, 4, 5, 6, 7, 8, 9))
        assertEquals(
            "tunProxyStats running=1 activeTcp=2 totalTcp=3 tcpFailed=4 dnsOk=5 dnsFailed=6 udpDropped=7 packetsIn=8 packetsOut=9",
            text,
        )
    }
}
