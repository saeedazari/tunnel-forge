package io.github.evokelektrique.tunnelforge

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.system.OsConstants
import android.util.Log
import androidx.annotation.Keep
import androidx.core.app.NotificationCompat
import java.net.InetAddress

/**
 * Captures all device traffic in proxy-only mode.
 *
 * Owns an Android TUN whose packets are terminated by a Go netstack ([VpnBridge.nativeTunProxyStart])
 * and forwarded to the local SOCKS5 listener, which in turn chains through the L2TP tunnel and the
 * optional upstream proxy. This app is excluded from the TUN so the tunnel's own sockets and the
 * loopback proxy path never loop back into it.
 */
@Keep
class TunProxyService : VpnService() {
    private var tun: ParcelFileDescriptor? = null
    private var statsThread: Thread? = null

    @Volatile
    private var running = false

    override fun onCreate() {
        super.onCreate()
        instance = this
    }

    override fun onDestroy() {
        stopCapture("destroy")
        instance = null
        super.onDestroy()
    }

    override fun onRevoke() {
        VpnTunnelEvents.emitEngineLog(Log.WARN, TAG, "VPN permission revoked; whole-device capture stopped")
        stopCapture("revoked")
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopCapture("stop action")
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return START_NOT_STICKY
            }
            ACTION_START -> {
                startForegroundWithType(buildNotification())
                val socksPort = intent.getIntExtra(EXTRA_SOCKS_PORT, 0)
                val dns = intent.getIntArrayExtra(EXTRA_DNS_IPV4) ?: DEFAULT_DNS_IPV4
                if (!startCapture(socksPort, dns)) {
                    stopForeground(STOP_FOREGROUND_REMOVE)
                    stopSelf()
                    return START_NOT_STICKY
                }
                return START_NOT_STICKY
            }
            else -> {
                if (!running) stopSelf()
                return START_NOT_STICKY
            }
        }
    }

    private fun startCapture(socksPort: Int, dns: IntArray): Boolean {
        stopCapture("restart")
        if (socksPort !in 1..65535 || dns.size < 8) {
            VpnTunnelEvents.emitEngineLog(Log.ERROR, TAG, "Whole-device capture rejected: bad arguments socks=$socksPort")
            return false
        }
        try {
            val builder =
                Builder()
                    .setSession(getString(R.string.vpn_session_name))
                    .setMtu(TUN_MTU)
                    .addAddress(TUN_ADDRESS_V4, 32)
                    .addRoute("0.0.0.0", 0)
                    .addDnsServer(TUN_DNS_V4)
                    // IPv6 is routed into the TUN and dropped there so it cannot bypass the proxy.
                    .addAddress(TUN_ADDRESS_V6, 128)
                    .addRoute("::", 0)
                    .addDisallowedApplication(packageName)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                builder.setMetered(false)
            }
            val pfd =
                builder.establish() ?: run {
                    VpnTunnelEvents.emitEngineLog(
                        Log.ERROR,
                        TAG,
                        "Whole-device capture could not start: VPN permission missing or revoked",
                    )
                    return false
                }
            val rc = VpnBridge.nativeTunProxyStart(pfd.fd, TUN_MTU, socksPort, dns)
            if (rc != 0) {
                try {
                    pfd.close()
                } catch (_: Exception) {
                }
                VpnTunnelEvents.emitEngineLog(
                    Log.ERROR,
                    TAG,
                    "Whole-device capture engine failed rc=$rc error=${VpnBridge.nativeTunProxyLastError()}",
                )
                return false
            }
            tun = pfd
            running = true
            VpnTunnelEvents.emitEngineLog(
                Log.INFO,
                TAG,
                "Whole-device capture active socks=127.0.0.1:$socksPort dns=${formatDns(dns)} (this app is excluded)",
            )
            startStatsThread()
            return true
        } catch (e: Exception) {
            VpnTunnelEvents.emitEngineLog(
                Log.ERROR,
                TAG,
                "Whole-device capture failed: ${e.javaClass.simpleName}: ${e.message}",
            )
            stopCapture("start failure")
            return false
        }
    }

    private fun stopCapture(reason: String) {
        val wasRunning = running
        running = false
        statsThread?.interrupt()
        statsThread = null
        if (wasRunning || tun != null) {
            VpnBridge.nativeTunProxyStop()
        }
        try {
            tun?.close()
        } catch (_: Exception) {
        }
        tun = null
        if (wasRunning) {
            VpnTunnelEvents.emitEngineLog(Log.INFO, TAG, "Whole-device capture stopped reason=$reason")
        }
    }

    private fun startStatsThread() {
        val thread =
            Thread(
                {
                    var first = true
                    try {
                        while (running) {
                            Thread.sleep(if (first) FIRST_STATS_DELAY_MS else STATS_INTERVAL_MS)
                            first = false
                            if (!running) break
                            val error = VpnBridge.nativeTunProxyLastError()
                            VpnTunnelEvents.emitEngineLog(
                                Log.INFO,
                                TAG,
                                formatTunProxyStats(VpnBridge.nativeTunProxyStats()) +
                                    if (error.isBlank()) "" else " lastError=$error",
                            )
                        }
                    } catch (_: InterruptedException) {
                    }
                },
                "tunproxy-stats",
            )
        thread.isDaemon = true
        statsThread = thread
        thread.start()
    }

    private fun buildNotification(): Notification {
        createChannelIfNeeded()
        val launchIntent = packageManager.getLaunchIntentForPackage(packageName)
        val pending =
            PendingIntent.getActivity(
                this,
                0,
                launchIntent,
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
            )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.vpn_notification_title))
            .setContentText("Routing all device traffic through the proxy")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(pending)
            .setOngoing(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .build()
    }

    private fun startForegroundWithType(notification: Notification) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            @Suppress("DEPRECATION")
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun createChannelIfNeeded() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        nm.createNotificationChannel(
            NotificationChannel(
                CHANNEL_ID,
                getString(R.string.vpn_notification_channel_name),
                NotificationManager.IMPORTANCE_LOW,
            ),
        )
    }

    companion object {
        private const val TAG = "TunProxyService"
        const val ACTION_START = "io.github.evokelektrique.tunnelforge.action.TUNPROXY_START"
        const val ACTION_STOP = "io.github.evokelektrique.tunnelforge.action.TUNPROXY_STOP"
        const val EXTRA_SOCKS_PORT = "socksPort"
        const val EXTRA_DNS_IPV4 = "dnsIpv4"

        private const val CHANNEL_ID = "tunnel_forge_tunproxy"
        private const val NOTIFICATION_ID = 7103
        private const val FIRST_STATS_DELAY_MS = 5_000L
        private const val STATS_INTERVAL_MS = 15_000L

        internal const val TUN_MTU = 1500
        internal const val TUN_ADDRESS_V4 = "198.18.0.1"
        internal const val TUN_DNS_V4 = "198.18.0.2"
        internal const val TUN_ADDRESS_V6 = "fd00:e0e0::1"

        /** Used when the profile has no manual IPv4 DNS; queries leave through the proxy chain. */
        internal val DEFAULT_DNS_IPV4 = intArrayOf(1, 1, 1, 1, 8, 8, 8, 8)

        @Volatile
        private var instance: TunProxyService? = null

        /** Starts capture; the caller must already hold the VPN permission. */
        @JvmStatic
        internal fun start(context: Context, socksPort: Int, dnsServers: List<DnsServerConfig>) {
            val intent =
                Intent(context, TunProxyService::class.java).apply {
                    action = ACTION_START
                    putExtra(EXTRA_SOCKS_PORT, socksPort)
                    putExtra(EXTRA_DNS_IPV4, dnsIpv4For(dnsServers))
                }
            context.startForegroundService(intent)
        }

        /** Stops capture if it is running; a no-op otherwise. */
        @JvmStatic
        fun stopActive(reason: String) {
            val svc = instance ?: return
            VpnTunnelEvents.emitEngineLog(Log.DEBUG, TAG, "Stopping whole-device capture reason=$reason")
            svc.stopCapture(reason)
            try {
                svc.stopForeground(STOP_FOREGROUND_REMOVE)
                svc.stopSelf()
            } catch (e: Exception) {
                AppLog.w(TAG, "stopActive", e)
            }
        }

        /** Up to two literal IPv4 resolvers from the profile, topped up with public defaults. */
        internal fun dnsIpv4For(dnsServers: List<DnsServerConfig>): IntArray {
            val literals =
                dnsServers
                    .mapNotNull { it.host.trim().toIpv4LiteralOrNull() }
                    .distinct()
                    .take(2)
            if (literals.isEmpty()) return DEFAULT_DNS_IPV4
            val out = IntArray(8)
            literals.forEachIndexed { i, literal ->
                InetAddress.getByName(literal).address.forEachIndexed { j, b -> out[i * 4 + j] = b.toInt() and 0xff }
            }
            return out
        }

        internal fun formatDns(dns: IntArray): String =
            listOf(0, 4)
                .map { base -> (0..3).joinToString(".") { dns.getOrElse(base + it) { 0 }.toString() } }
                .filter { it != "0.0.0.0" }
                .joinToString(",")

        /** Formats the positional native stats array; keep aligned with tf_tunproxy_stats in Go. */
        internal fun formatTunProxyStats(stats: IntArray): String {
            fun at(index: Int): Int = stats.getOrElse(index) { -1 }
            return "tunProxyStats running=${at(0)} activeTcp=${at(1)} totalTcp=${at(2)} tcpFailed=${at(3)} " +
                "dnsOk=${at(4)} dnsFailed=${at(5)} udpDropped=${at(6)} packetsIn=${at(7)} packetsOut=${at(8)}"
        }
    }
}
