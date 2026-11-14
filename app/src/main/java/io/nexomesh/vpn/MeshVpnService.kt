package io.nexomesh.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor

class MeshVpnService : VpnService() {
    companion object {
        @Volatile
        var lastKnownAlwaysOn: Boolean = false
            private set

        @Volatile
        var bunkerMode: Boolean = false

        @Volatile
        var blockedPacketsCount: Long = 0L

        val quarantinedIps = java.util.Collections.synchronizedSet(mutableSetOf<String>())

        fun recordSuspiciousTraffic(ip: String, reason: String) {
            blockedPacketsCount += 1L
            quarantinedIps.add(ip)
        }

        fun releaseQuarantinedIp(ip: String) {
            quarantinedIps.remove(ip)
        }

        fun isRealAlwaysOnActive(context: Context): Boolean {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
                return context.getSharedPreferences("nexomesh_prefs", Context.MODE_PRIVATE)
                    .getBoolean("keepalive_vpn_legacy_pass", false)
            }
            if (lastKnownAlwaysOn) return true
            return context.getSharedPreferences("nexomesh_prefs", Context.MODE_PRIVATE)
                .getBoolean("real_vpn_always_on", false)
        }
    }

    private var tunFd: ParcelFileDescriptor? = null
    private var activeIp: String? = null
    private var activeMtu: Int = -1

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == "STOP") {
            stopMesh()
            stopSelf()
            return START_NOT_STICKY
        }

        val localIp = intent?.getStringExtra("VIRTUAL_IP") ?: "10.0.0.1"
        val mtu = intent?.getIntExtra("MTU", 1280) ?: 1280
        val keepalive = intent?.getIntExtra("KEEPALIVE_SEC", 15) ?: 15
        val stun = intent?.getStringExtra("STUN_SERVER") ?: "stun.l.google.com:19302"

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val osAlwaysOn = this.isAlwaysOn
            lastKnownAlwaysOn = osAlwaysOn
            getSharedPreferences("nexomesh_prefs", MODE_PRIVATE)
                .edit()
                .putBoolean("real_vpn_always_on", osAlwaysOn)
                .apply()
        }

        if (tunFd != null && activeIp == localIp && activeMtu == mtu) {
            return START_STICKY
        }

        ensureNotification(localIp)

        // Split-tunnel puro para 10.0.0.0/24: NO sobreescribimos DNS (addDnsServer)
        // para que todo el tráfico normal a internet y DNS sigan saliendo por Wi-Fi / 4G / Ethernet.
        val builder = Builder()
            .setSession("NexoMesh P2P")
            .addAddress(localIp, 24)
            .addRoute("10.0.0.0", 24)
            .setMtu(mtu)
            .setBlocking(false)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
            val underlying = findUnderlyingPhysicalNetworks()
            if (underlying.isNotEmpty()) {
                builder.setUnderlyingNetworks(underlying)
            }
        }

        try {
            builder.addDisallowedApplication(packageName)
        } catch (_: Exception) {
        }

        tunFd?.close()
        tunFd = builder.establish()
        activeIp = localIp
        activeMtu = mtu
        val fd = tunFd?.fd ?: -1
        if (fd >= 0 && RustCoreBridge.isNativeReady()) {
            RustCoreBridge.startTunnel(fd, localIp, stun, keepalive)
        }
        return START_STICKY
    }

    private fun findUnderlyingPhysicalNetworks(): Array<Network> {
        return try {
            val cm = getSystemService(ConnectivityManager::class.java) ?: return emptyArray()
            cm.allNetworks.filter { net ->
                val caps = cm.getNetworkCapabilities(net)
                caps != null &&
                    !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
                    caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            }.toTypedArray()
        } catch (_: Exception) {
            emptyArray()
        }
    }

    private fun ensureNotification(localIp: String) {
        val channelId = "nexomesh_vpn_channel"
        val manager = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                channelId,
                "NexoMesh Túnel P2P",
                NotificationManager.IMPORTANCE_LOW
            )
            manager.createNotificationChannel(channel)
        }
        val notification = Notification.Builder(this, channelId)
            .setContentTitle("NexoMesh VPN Activo")
            .setContentText("Red privada $localIp · Internet directo activo")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .build()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(101, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(101, notification)
        }
    }

    private fun stopMesh() {
        if (RustCoreBridge.isNativeReady()) {
            RustCoreBridge.stopTunnel()
        }
        tunFd?.close()
        tunFd = null
        activeIp = null
        activeMtu = -1
    }

    override fun onRevoke() {
        lastKnownAlwaysOn = false
        getSharedPreferences("nexomesh_prefs", MODE_PRIVATE)
            .edit()
            .putBoolean("real_vpn_always_on", false)
            .apply()
        stopMesh()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopMesh()
        super.onDestroy()
    }
}
