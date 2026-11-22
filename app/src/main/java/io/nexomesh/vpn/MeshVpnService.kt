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
import android.os.PowerManager
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.ConcurrentHashMap

class MeshVpnService : VpnService() {
    data class PeerEndpointInfo(
        val virtualIp: String,
        val name: String,
        val stunEndpoint: String,
        val lanEndpoint: String,
        val peerPublicKey: String = ""
    )

    companion object {
        const val MESH_UDP_PORT = 51820

        @Volatile
        var lastKnownAlwaysOn: Boolean = false
            private set

        @Volatile
        var isServiceRunning: Boolean = false
            private set

        @Volatile
        var isWakeLockHeld: Boolean = false
            private set

        @Volatile
        var localVirtualIp: String = "10.0.0.1"

        @Volatile
        var localPublicKey: String = ""

        @Volatile
        var bunkerMode: Boolean = false

        @Volatile
        var guardianEnabled: Boolean = false

        @Volatile
        var blockedPacketsCount: Long = 0L

        // Telemetría real: contadores atómicos y RTT medido NM_HELLO -> NM_ACK
        @Volatile
        var bytesSentTotal: Long = 0L
            private set

        @Volatile
        var bytesReceivedTotal: Long = 0L
            private set

        private val helloSentAtMs = ConcurrentHashMap<String, Long>()

        @Volatile
        var lastRttMs: Long = 0L
            private set

        private val rttByPeer = ConcurrentHashMap<String, Long>()

        fun getPeerRttMs(peerVip: String): Long = rttByPeer[peerVip] ?: 0L

        fun recordHelloSent(peerVip: String) {
            helloSentAtMs[peerVip] = System.currentTimeMillis()
        }

        fun recordAckReceived(peerVip: String) {
            val sent = helloSentAtMs.remove(peerVip) ?: return
            val rtt = (System.currentTimeMillis() - sent).coerceIn(1L, 10_000L)
            lastRttMs = rtt
            rttByPeer[peerVip] = rtt
        }

        fun addTxBytes(n: Int) { bytesSentTotal += n }

        fun addRxBytes(n: Int) { bytesReceivedTotal += n }

        fun resetCounters() {
            bytesSentTotal = 0L
            bytesReceivedTotal = 0L
            lastRttMs = 0L
        }

        val quarantinedIps = java.util.Collections.synchronizedSet(mutableSetOf<String>())
        val peerRoutes = ConcurrentHashMap<String, PeerEndpointInfo>()
        val learnedSocketAddrs = ConcurrentHashMap<String, InetSocketAddress>()
        val lastDirectRxMs = ConcurrentHashMap<String, Long>()

        @Volatile
        private var activeUdpSocket: DatagramSocket? = null

        @Volatile
        private var peerDiscoveredListener: ((virtualIp: String, name: String, remoteAddr: String) -> Unit)? = null

        fun registerDiscoveredPeerCallback(cb: ((virtualIp: String, name: String, remoteAddr: String) -> Unit)?) {
            peerDiscoveredListener = cb
        }

        fun updateLocalVirtualIp(ip: String) {
            if (ip.startsWith("10.0.0.")) {
                localVirtualIp = ip
            }
        }

        fun updatePeers(list: List<PeerEndpointInfo>) {
            val activeIps = list.map { it.virtualIp }.toSet()
            for (k in peerRoutes.keys) {
                if (!activeIps.contains(k)) {
                    peerRoutes.remove(k)
                    learnedSocketAddrs.remove(k)
                    lastDirectRxMs.remove(k)
                }
            }
            for (item in list) {
                peerRoutes[item.virtualIp] = item
                // Inicializar sesión cifrada con este par (X25519 + ChaCha20-Poly1305)
                if (RustCoreBridge.isNativeReady() && localPublicKey.isNotBlank() && item.peerPublicKey.isNotBlank()) {
                    val ok = RustCoreBridge.initSession(item.virtualIp, localPublicKey, item.peerPublicKey)
                    android.util.Log.i("NexoMeshRelay", "initSession(${item.virtualIp})=$ok")
                }
            }
        }

        fun sendHelloBurstToPeer(lanEndpoint: String, stunEndpoint: String, myIp: String, myName: String) {
            val sock = activeUdpSocket ?: return
            val helloBytes = "NM_HELLO|$myIp|$myName|$lanEndpoint".toByteArray(Charsets.UTF_8)
            val targets = listOf(lanEndpoint, stunEndpoint)
                .flatMap { raw -> raw.split(",").map { it.trim() } }
            for (raw in targets) {
                val parsed = parseHostPort(raw, MESH_UDP_PORT) ?: continue
                try {
                    val addr = InetAddress.getByName(parsed.first)
                    sock.send(DatagramPacket(helloBytes, helloBytes.size, addr, parsed.second))
                } catch (_: Exception) {
                }
            }
        }

        fun parseHostPort(raw: String?, defaultPort: Int): Pair<String, Int>? {
            if (raw.isNullOrBlank()) return null
            val clean = raw.trim()
            if (clean.contains(" ") || clean.equals("STUN directo", ignoreCase = true)) return null
            val parts = clean.split(":")
            val host = parts[0].trim()
            if (host.isEmpty() || host == "0.0.0.0" || host.startsWith("10.0.0.")) return null
            val port = parts.getOrNull(1)?.toIntOrNull() ?: defaultPort
            return host to port
        }

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
    private var udpSocket: DatagramSocket? = null
    private var wakeLock: PowerManager.WakeLock? = null
    private var activeIp: String? = null
    private var activeMtu: Int = -1
    @Volatile
    private var forwardRunning = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == "STOP") {
            stopMesh()
            stopSelf()
            return START_NOT_STICKY
        }

        val prefs = getSharedPreferences("nexomesh_prefs", MODE_PRIVATE)
        val savedIp = prefs.getString("my_virtual_ip", "10.0.0.1") ?: "10.0.0.1"
        val localIp = intent?.getStringExtra("VIRTUAL_IP") ?: savedIp
        localVirtualIp = localIp
        localPublicKey = prefs.getString("host_pub_key", "") ?: ""
        if (RustCoreBridge.isNativeReady() && localPublicKey.isNotBlank()) {
            for (item in peerRoutes.values) {
                val pk = item.peerPublicKey.ifBlank { prefs.getString("peer_pk_${item.virtualIp}", "") ?: "" }
                if (pk.isNotBlank()) {
                    val ok = RustCoreBridge.initSession(item.virtualIp, localPublicKey, pk)
                    android.util.Log.i("NexoMeshRelay", "onStart initSession(${item.virtualIp})=$ok")
                }
            }
        }
        val mtu = intent?.getIntExtra("MTU", 1280) ?: 1280
        val keepalive = intent?.getIntExtra("KEEPALIVE_SEC", 15) ?: 15
        val stun = intent?.getStringExtra("STUN_SERVER") ?: "stun.l.google.com:19302"

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val osAlwaysOn = this.isAlwaysOn
            lastKnownAlwaysOn = osAlwaysOn
            prefs.edit().putBoolean("real_vpn_always_on", osAlwaysOn).apply()
        }

        if (tunFd != null && activeIp == localIp && activeMtu == mtu && forwardRunning) {
            ensureRelayConnected(intent, prefs, localIp)
            return START_STICKY
        }

        ensureNotification(localIp)
        acquireWakeLock()

        // Split-tunnel puro para 10.0.0.0/24: NO sobreescribimos DNS (addDnsServer) ni agregamos
        // addDisallowedApplication(packageName), así nuestros sockets P2P a 10.0.0.x SÍ pasan
        // por tun0, mientras todo Internet/DNS sale directo por Wi-Fi / 4G / Ethernet.
        val builder = Builder()
            .setSession("NexoMesh P2P")
            .addAddress(localIp, 24)
            .addRoute("10.0.0.0", 24)
            .setMtu(mtu)
            .setBlocking(true)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
            val underlying = findUnderlyingPhysicalNetworks()
            if (underlying.isNotEmpty()) {
                builder.setUnderlyingNetworks(underlying)
            }
        }

        stopForwardLoops()
        tunFd?.close()
        tunFd = builder.establish()
        activeIp = localIp
        activeMtu = mtu
        isServiceRunning = tunFd != null

        val fd = tunFd?.fd ?: -1
        if (fd >= 0 && RustCoreBridge.isNativeReady()) {
            RustCoreBridge.startTunnel(fd, localIp, stun, keepalive)
        }
        if (tunFd != null) {
            startForwardLoops(localIp, keepalive)
            ensureRelayConnected(intent, prefs, localIp)
            // El receptor :51821 vive en el servicio, no en la Activity: arranca
            // automaticamente con la VPN y sobrevive a recreaciones de pantalla.
            FileTransferCore.start(this)
        }
        return START_STICKY
    }

    private fun ensureRelayConnected(
        intent: Intent?,
        prefs: android.content.SharedPreferences,
        localIp: String
    ) {
        val relayUrl = intent?.getStringExtra("RELAY_URL")
            ?: prefs.getString("relay_url", "") ?: ""
        if (relayUrl.isNotBlank() && !RelayClient.isConnected()) {
            val id = localPublicKey.ifBlank { localIp }
            RelayClient.connect(relayUrl, id, "")
        }
    }

    private fun acquireWakeLock() {
        try {
            if (wakeLock == null) {
                val pm = getSystemService(PowerManager::class.java)
                wakeLock = pm?.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "NexoMesh::TunnelWakeLock")
            }
            if (wakeLock?.isHeld == false) {
                wakeLock?.acquire(12 * 60 * 60 * 1000L)
            }
            isWakeLockHeld = wakeLock?.isHeld == true
        } catch (_: Exception) {
            isWakeLockHeld = false
        }
    }

    private fun startForwardLoops(localIp: String, keepaliveSec: Int) {
        val descriptor = tunFd ?: return
        try {
            val sock = DatagramSocket(null).apply {
                reuseAddress = true
                bind(InetSocketAddress(MESH_UDP_PORT))
            }
            // Protegemos SOLO el socket UDP externo para que salga directo por Wi-Fi / 4G sin loop VPN
            protect(sock)
            udpSocket = sock
            activeUdpSocket = sock
        } catch (_: Exception) {
            return
        }

        forwardRunning = true
        val tunIn = FileInputStream(descriptor.fileDescriptor)
        val tunOut = FileOutputStream(descriptor.fileDescriptor)
        val lockWrite = Any()

            // Los frames que llegan por el relay WSS se descifran y se inyectan
            // en el TUN exactamente igual que los recibidos por UDP directo.
            RelayClient.onFrameReceived = { frame ->
                try {
                    if (frame.size >= 4 + 1) {
                        val senderLen = frame[3].toInt() and 0xFF
                        if (4 + senderLen < frame.size) {
                            val senderVip = String(frame, 4, senderLen, Charsets.UTF_8)
                            val packet = if (RustCoreBridge.isNativeReady()) {
                                RustCoreBridge.openPacket(senderVip, frame.copyOfRange(4 + senderLen, frame.size))
                            } else frame.copyOfRange(4 + senderLen, frame.size)
                            if (packet.isNotEmpty() && ((packet[0].toInt() ushr 4) and 0x0F) == 4) {
                                synchronized(lockWrite) { tunOut.write(packet, 0, packet.size) }
                                addRxBytes(packet.size)
                            } else {
                                android.util.Log.w("NexoMeshRelay", "openPacket vacío/inválido desde $senderVip (${frame.size}B)")
                            }
                        }
                    }
                } catch (_: Exception) {
                }
            }

        // 1. TUN -> UDP (:51820) encapsulador IPv4
        Thread {
            val buf = ByteArray(4096)
            while (forwardRunning) {
                try {
                    val len = tunIn.read(buf)
                    if (len <= 0) {
                        if (!forwardRunning) break
                        continue
                    }
                    if (len < 20 || ((buf[0].toInt() ushr 4) and 0x0F) != 4) continue
                    val srcIp = "${buf[12].toInt() and 0xFF}.${buf[13].toInt() and 0xFF}.${buf[14].toInt() and 0xFF}.${buf[15].toInt() and 0xFF}"
                    val dstIp = "${buf[16].toInt() and 0xFF}.${buf[17].toInt() and 0xFF}.${buf[18].toInt() and 0xFF}.${buf[19].toInt() and 0xFF}"
                    if (!dstIp.startsWith("10.0.0.") || dstIp == localIp) continue
                    if (quarantinedIps.contains(dstIp) || quarantinedIps.contains(srcIp)) {
                        blockedPacketsCount += 1L
                        continue
                    }
                    val proto = buf[9].toInt() and 0xFF
                    val ihl = (buf[0].toInt() and 0x0F) * 4
                    val dstPort = if ((proto == 6 || proto == 17) && len >= ihl + 4) {
                        ((buf[ihl + 2].toInt() and 0xFF) shl 8) or (buf[ihl + 3].toInt() and 0xFF)
                    } else 51820

                    if (dstPort in listOf(22, 23, 445, 3389, 5555) || (bunkerMode && dstPort != 51820 && dstPort != 51821)) {
                        blockedPacketsCount += 1L
                        continue
                    }
                    if (RustCoreBridge.isNativeReady() && !RustCoreBridge.inspectPacket(len, dstPort)) {
                        blockedPacketsCount += 1L
                        continue
                    }

                    // frame: NM1 | len(senderVip) | senderVip | ciphertext(AEAD)
                    val senderBytes = localIp.toByteArray(Charsets.UTF_8)
                    val packet = buf.copyOfRange(0, len)
                    val encrypted = if (RustCoreBridge.isNativeReady()) {
                        RustCoreBridge.sealPacket(dstIp, packet)
                    } else packet
                    if (encrypted.isEmpty()) {
                        android.util.Log.w("NexoMeshRelay", "sealPacket vacío para $dstIp (sin sesión)")
                        continue
                    }
                    val frame = ByteArray(4 + senderBytes.size + encrypted.size)
                    frame[0] = 'N'.code.toByte()
                    frame[1] = 'M'.code.toByte()
                    frame[2] = '1'.code.toByte()
                    frame[3] = senderBytes.size.toByte()
                    System.arraycopy(senderBytes, 0, frame, 4, senderBytes.size)
                    System.arraycopy(encrypted, 0, frame, 4 + senderBytes.size, encrypted.size)

                    val sock = udpSocket ?: continue
                    // Directo UDP solo si hubo tráfico/ACK reciente (<15s); si no,
                    // usar relay WSS (tipo Tailscale DERP) mientras sigue el hole-punch.
                    val directFresh = learnedSocketAddrs[dstIp] != null &&
                        (System.currentTimeMillis() - (lastDirectRxMs[dstIp] ?: 0L)) <= 15_000L
                    val target = resolveBestPeerTarget(dstIp, localIp)
                    var sent = false
                    if (directFresh && target != null) {
                        try {
                            sock.send(DatagramPacket(frame, frame.size, target.address, target.port))
                            addTxBytes(len)
                            sent = true
                        } catch (_: Exception) {
                        }
                    }
                    if (!sent && RelayClient.isConnected()) {
                        // Fallback DERP: UDP directo no confirmado -> relay WSS
                        if (RelayClient.send(frame)) {
                            addTxBytes(len)
                            sent = true
                        }
                    }
                    if (!sent && target != null) {
                        try {
                            sock.send(DatagramPacket(frame, frame.size, target.address, target.port))
                            addTxBytes(len)
                        } catch (_: Exception) {
                        }
                    }
                } catch (_: Exception) {
                    if (!forwardRunning) break
                }
            }
        }.apply { name = "NexoMesh-TunToUdp"; start() }

        // 2. UDP (:51820) -> TUN inyector IPv4 + receptor NM_HELLO
        Thread {
            val rxBuf = ByteArray(4200)
            while (forwardRunning) {
                try {
                    val pkt = DatagramPacket(rxBuf, rxBuf.size)
                    val sock = udpSocket ?: break
                    sock.receive(pkt)
                    val len = pkt.length
                    if (len < 8) continue
                    // STUN Binding Request sobre el socket del túnel: responder con el
                    // mismo puerto para que el mapped address sea el real.
                    if (len >= 20 && rxBuf[0] == 0x00.toByte() && rxBuf[1] == 0x01.toByte() &&
                        rxBuf[4] == 0x21.toByte() && rxBuf[5] == 0x12.toByte()) {
                        System.arraycopy(rxBuf, 0, rxBufCompat, 0, len)
                        respondStunOnTunnelSocket(pkt, sock, len)
                        continue
                    }
                    if (rxBuf[0] == 'N'.code.toByte() && rxBuf[1] == 'M'.code.toByte() && rxBuf[2] == '_'.code.toByte()) {
                        val msg = String(rxBuf, 0, len, Charsets.UTF_8)
                        if (msg.startsWith("NM_HELLO|") || msg.startsWith("NM_ACK|")) {
                            val parts = msg.split("|")
                            val peerVip = parts.getOrNull(1)?.trim() ?: ""
                            val peerName = parts.getOrNull(2)?.trim() ?: "Par P2P"
                            val senderIp = pkt.address?.hostAddress ?: ""
                            if (peerVip.startsWith("10.0.0.") && peerVip != localIp && senderIp.isNotEmpty()) {
                                val remote = InetSocketAddress(pkt.address, pkt.port)
                                learnedSocketAddrs[peerVip] = remote
                                lastDirectRxMs[peerVip] = System.currentTimeMillis()
                                peerDiscoveredListener?.invoke(peerVip, peerName, "$senderIp:${pkt.port}")
                                if (msg.startsWith("NM_ACK|")) {
                                    // ACK recibido: medimos RTT real desde el HELLO enviado a este par
                                    recordAckReceived(peerVip)
                                }
                                if (msg.startsWith("NM_HELLO|")) {
                                    val ack = "NM_ACK|$localIp|${Build.MODEL}|direct".toByteArray(Charsets.UTF_8)
                                    try {
                                        sock.send(DatagramPacket(ack, ack.size, pkt.address, pkt.port))
                                    } catch (_: Exception) {
                                    }
                                }
                            }
                        }
                    } else if (rxBuf[0] == 'N'.code.toByte() && rxBuf[1] == 'M'.code.toByte() && rxBuf[2] == '1'.code.toByte() && len >= 24) {
                        if (rxBuf[3] == 0x01.toByte()) {
                            // Formato legacy (plaintext) por compatibilidad
                            val ipLen = len - 4
                            if (((rxBuf[4].toInt() ushr 4) and 0x0F) != 4) continue
                            val srcIp = "${rxBuf[16].toInt() and 0xFF}.${rxBuf[17].toInt() and 0xFF}.${rxBuf[18].toInt() and 0xFF}.${rxBuf[19].toInt() and 0xFF}"
                            if (quarantinedIps.contains(srcIp)) { blockedPacketsCount += 1L; continue }
                            if (srcIp.startsWith("10.0.0.") && srcIp != localIp && pkt.address != null) {
                                learnedSocketAddrs[srcIp] = InetSocketAddress(pkt.address, pkt.port)
                            }
                            synchronized(lockWrite) { tunOut.write(rxBuf, 4, ipLen) }
                        } else {
                            // Formato cifrado: NM1 | len(senderVip) | senderVip | ciphertext
                            val senderLen = rxBuf[3].toInt() and 0xFF
                            if (senderLen <= 0 || 4 + senderLen >= len) continue
                            val senderVip = String(rxBuf, 4, senderLen, Charsets.UTF_8)
                            val frame = rxBuf.copyOfRange(4 + senderLen, len)
                            val packet = if (RustCoreBridge.isNativeReady()) {
                                RustCoreBridge.openPacket(senderVip, frame)
                            } else frame
                            if (packet.isEmpty() || ((packet[0].toInt() ushr 4) and 0x0F) != 4) continue
                            val srcIp = "${packet[12].toInt() and 0xFF}.${packet[13].toInt() and 0xFF}.${packet[14].toInt() and 0xFF}.${packet[15].toInt() and 0xFF}"
                            if (quarantinedIps.contains(srcIp)) { blockedPacketsCount += 1L; continue }
                            if (senderVip.startsWith("10.0.0.") && senderVip != localIp && pkt.address != null) {
                                learnedSocketAddrs[senderVip] = InetSocketAddress(pkt.address, pkt.port)
                                lastDirectRxMs[senderVip] = System.currentTimeMillis()
                            }
                            synchronized(lockWrite) { tunOut.write(packet, 0, packet.size) }
                            addRxBytes(packet.size)
                        }
                    }
                } catch (_: Exception) {
                    if (!forwardRunning) break
                }
            }
        }.apply { name = "NexoMesh-UdpToTun"; start() }

        // 3. Keepalive + NAT Hole-Punch periódico
        Thread {
            val intervalMs = keepaliveSec.coerceIn(5, 30) * 1000L
            while (forwardRunning) {
                try {
                    val sock = udpSocket
                    if (sock != null) {
                        val hello = "NM_HELLO|$localIp|${Build.MODEL}|keepalive".toByteArray(Charsets.UTF_8)
                        for (peer in peerRoutes.values) {
                            for (target in resolvePeerTargets(peer.virtualIp)) {
                                try {
                                    sock.send(DatagramPacket(hello, hello.size, target.address, target.port))
                                    recordHelloSent(peer.virtualIp)
                                } catch (_: Exception) {
                                }
                            }
                        }
                    }
                    Thread.sleep(intervalMs)
                } catch (_: InterruptedException) {
                    break
                } catch (_: Exception) {
                }
            }
        }.apply { name = "NexoMesh-Keepalive"; start() }
    }

    /**
     * Responde un STUN Binding Request usando el MISMO socket UDP :51820 del túnel,
     * de modo que el puerto público descubierto coincide con el puerto real (evita
     * el problema de NAT simétrico del socket efímero deMainActivity).
     */
    private fun respondStunOnTunnelSocket(pkt: DatagramPacket, sock: DatagramSocket, len: Int) {
        if (len < 20 || rxBufCompat[0] != 0x00.toByte() || rxBufCompat[1] != 0x01.toByte()) return
        if ((rxBufCompat[4].toInt() and 0xFF) != 0x21 || (rxBufCompat[5].toInt() and 0xFF) != 0x12) return
        val resp = ByteArray(32)
        resp[0] = 0x01; resp[1] = 0x01
        resp[2] = 0x00; resp[3] = 0x0C
        resp[4] = 0x21; resp[5] = 0x12; resp[6] = 0xA4.toByte(); resp[7] = 0x42
        System.arraycopy(rxBufCompat, 8, resp, 8, 12)
        resp[20] = 0x00; resp[21] = 0x20; resp[22] = 0x00; resp[23] = 0x08
        resp[24] = 0x00; resp[25] = 0x01
        val port = pkt.port xor 0x2112
        resp[26] = (port ushr 8).toByte(); resp[27] = port.toByte()
        val ip = pkt.address?.hostAddress?.split(".")?.map { it.toIntOrNull() ?: 0 } ?: return
        resp[28] = (ip[0] xor 0x21).toByte(); resp[29] = (ip[1] xor 0x12).toByte()
        resp[30] = (ip[2] xor 0xA4).toByte(); resp[31] = (ip[3] xor 0x42).toByte()
        try { sock.send(DatagramPacket(resp, resp.size, pkt.address, pkt.port)) } catch (_: Exception) {}
    }

    private val rxBufCompat = ByteArray(4200)

    private fun resolvePeerTargets(dstVirtualIp: String): List<InetSocketAddress> {
        val list = mutableListOf<InetSocketAddress>()
        learnedSocketAddrs[dstVirtualIp]?.let { list.add(it) }
        val info = peerRoutes[dstVirtualIp]
        if (info != null) {
            // Los endpoints pueden contener varias direcciones separadas por coma
            // (invitaciones con multiples candidatos LAN). Probar todas.
            val rawTargets = listOf(info.lanEndpoint, info.stunEndpoint)
                .flatMap { raw -> raw.split(",").map { it.trim() } }
            for (raw in rawTargets) {
                parseHostPort(raw, MESH_UDP_PORT)?.let { (h, p) ->
                    try {
                        val isa = InetSocketAddress(InetAddress.getByName(h), p)
                        if (!list.contains(isa)) list.add(isa)
                    } catch (_: Exception) {
                    }
                }
            }
        }
        return list
    }

    /**
     * Devuelve UN solo destino para un paquete: aprendido de los paquetes reales
     * del par, o el primero de la ruta configurada. Nunca la IP local.
     */
    private fun resolveBestPeerTarget(dstVirtualIp: String, localIp: String): InetSocketAddress? {
        if (dstVirtualIp == localIp || dstVirtualIp.startsWith("10.0.0.") && dstVirtualIp == localIp) return null
        learnedSocketAddrs[dstVirtualIp]?.let { return it }
        return resolvePeerTargets(dstVirtualIp).firstOrNull()
    }

    private fun stopForwardLoops() {
        forwardRunning = false
        activeUdpSocket = null
        try { udpSocket?.close() } catch (_: Exception) {}
        udpSocket = null
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
        stopForwardLoops()
        RelayClient.close()
        FileTransferCore.stop()
        if (RustCoreBridge.isNativeReady()) {
            RustCoreBridge.stopTunnel()
        }
        try { tunFd?.close() } catch (_: Exception) {}
        tunFd = null
        activeIp = null
        activeMtu = -1
        isServiceRunning = false
        try {
            if (wakeLock?.isHeld == true) wakeLock?.release()
        } catch (_: Exception) {
        }
        isWakeLockHeld = false
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
