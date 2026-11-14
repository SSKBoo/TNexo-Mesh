package io.nexomesh.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor

class MeshVpnService : VpnService() {
    private var tunFd: ParcelFileDescriptor? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == "STOP") {
            stopMesh()
            stopSelf()
            return START_NOT_STICKY
        }

        val localIp = intent?.getStringExtra("VIRTUAL_IP") ?: "10.0.0.1"
        val mtu = intent?.getIntExtra("MTU", 1280) ?: 1280
        val keepalive = intent?.getIntExtra("KEEPALIVE_SEC", 10) ?: 10
        val stun = intent?.getStringExtra("STUN_SERVER") ?: "stun.l.google.com:19302"

        ensureNotification(localIp)

        val builder = Builder()
            .setSession("NexoMesh P2P")
            .addAddress(localIp, 24)
            .addRoute("10.0.0.0", 24)
            .addDnsServer("10.0.0.1")
            .setMtu(mtu)
            .setBlocking(false)

        try {
            builder.addDisallowedApplication(packageName)
        } catch (_: Exception) {
        }

        tunFd?.close()
        tunFd = builder.establish()
        val fd = tunFd?.fd ?: -1
        if (fd >= 0 && RustCoreBridge.isNativeReady()) {
            RustCoreBridge.startTunnel(fd, localIp, stun, keepalive)
        }
        return START_STICKY
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
            .setContentText("Red privada $localIp · Noise IKpsk2")
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
    }

    override fun onDestroy() {
        stopMesh()
        super.onDestroy()
    }
}
