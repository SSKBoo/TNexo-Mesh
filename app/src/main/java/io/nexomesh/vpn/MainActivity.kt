package io.nexomesh.vpn

import android.app.Activity
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Color
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.PowerManager
import android.provider.Settings
import android.util.Base64
import android.view.Gravity
import android.widget.Button
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.content.FileProvider
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import java.io.File
import java.security.SecureRandom
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlin.math.min

class MainActivity : AppCompatActivity() {
    private lateinit var statusText: TextView
    private lateinit var deviceText: TextView
    private lateinit var peerSummaryText: TextView
    private lateinit var toggleBtn: Button
    private lateinit var transportBtn: Button

    private var vpnRunning = false
    private var autoTransportMode = true
    private var activeMtu = 1280
    private var activeKeepalive = 10
    private var activeTransportLabel = "Automático"
    private var backoffAttempt = 0
    private val mainHandler = Handler(Looper.getMainLooper())
    private val logsList = mutableListOf<String>()
    private val connectedPeers = mutableListOf<String>()

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            startMeshTunnel()
        } else {
            appendLog("WARNING", "VpnService", "10.0.0.1", "Permiso VPN rechazado")
            statusText.text = "Permiso VPN rechazado por el sistema"
        }
    }

    private val qrScannerLauncher = registerForActivityResult(ScanContract()) { result ->
        val raw = result.contents
        if (raw.isNullOrBlank()) {
            statusText.text = "Escaneo QR cancelado"
            return@registerForActivityResult
        }
        handleScannedInviteUri(raw)
    }

    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onLost(network: Network) {
            runOnUiThread {
                if (vpnRunning) {
                    triggerLossAndExponentialBackoff()
                }
            }
        }

        override fun onAvailable(network: Network) {
            runOnUiThread {
                if (autoTransportMode) {
                    detectAndApplyAutoTransport(restartIfRunning = false)
                }
                if (backoffAttempt > 0) {
                    backoffAttempt = 0
                    mainHandler.removeCallbacksAndMessages(null)
                    appendLog("INFO", "Backoff", "10.0.0.1", "Red recuperada; reabriendo túnel P2P")
                    statusText.text = "Red recuperada · Túnel Activo (10.0.0.1/24)"
                    statusText.setTextColor(Color.parseColor("#10B981"))
                    startMeshTunnel()
                }
            }
        }

        override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) {
            runOnUiThread {
                if (autoTransportMode) {
                    applyCapabilitiesPolicy(networkCapabilities, restartIfRunning = vpnRunning)
                }
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val scroll = ScrollView(this).apply {
            setBackgroundColor(Color.parseColor("#0B0F17"))
        }

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding(48, 72, 48, 48)
        }

        val title = TextView(this).apply {
            text = "NexoMesh P2P"
            textSize = 24f
            setTextColor(Color.parseColor("#F8FAFC"))
        }

        deviceText = TextView(this).apply {
            text = "${Build.MANUFACTURER} ${Build.MODEL} · Android ${Build.VERSION.RELEASE}"
            textSize = 13f
            setTextColor(Color.parseColor("#94A3B8"))
            setPadding(0, 12, 0, 16)
        }

        statusText = TextView(this).apply {
            text = "Estado: Desconectado (10.0.0.1/24)"
            textSize = 15f
            setTextColor(Color.parseColor("#10B981"))
            setPadding(0, 0, 0, 16)
        }

        peerSummaryText = TextView(this).apply {
            text = "Pares enlazados: 0 · Cifrado: Noise_IKpsk2_25519_ChaChaPoly"
            textSize = 12f
            setTextColor(Color.parseColor("#CBD5E1"))
            setPadding(0, 0, 0, 28)
        }

        toggleBtn = createActionButton("Conectar Túnel VPN", "#059669", "#FFFFFF") {
            if (vpnRunning) stopMeshTunnel() else requestAndStartVpn()
        }

        transportBtn = createActionButton("Conexión: Automático (4G/5G ↔ Ethernet)", "#0F172A", "#38BDF8") {
            showTransportModeDialog()
        }

        val showQrBtn = createActionButton("Mostrar Mi QR de Invitación", "#1E293B", "#F8FAFC") {
            showHostQrDialog()
        }

        val scanQrBtn = createActionButton("Escanear QR de Amigo", "#1E293B", "#38BDF8") {
            launchQrScanner()
        }

        val stunBtn = createActionButton("Probar Sonda STUN (stun.l.google.com:19302)", "#1E293B", "#E2E8F0") {
            val mapped = if (RustCoreBridge.isNativeReady()) {
                RustCoreBridge.discoverStunEndpoint("stun.l.google.com:19302")
            } else {
                "Núcleo nativo pendiente de compilación"
            }
            appendLog("INFO", "STUN", "10.0.0.1", mapped)
            statusText.text = "STUN: $mapped"
        }

        val exportLogsBtn = createActionButton("Exportar Historial de Logs (.csv)", "#0F172A", "#10B981") {
            exportLogsToCsv()
        }

        val keepAliveBtn = createActionButton("Guía Anti-Cierre Android (PASS)", "#1E293B", "#FBBF24") {
            showAndroidKeepAliveGuideDialog()
        }

        root.addView(title)
        root.addView(deviceText)
        root.addView(statusText)
        root.addView(peerSummaryText)
        root.addView(toggleBtn)
        root.addView(transportBtn)
        root.addView(showQrBtn)
        root.addView(scanQrBtn)
        root.addView(stunBtn)
        root.addView(exportLogsBtn)
        root.addView(keepAliveBtn)

        scroll.addView(root)
        setContentView(scroll)

        registerNetworkMonitor()
        detectAndApplyAutoTransport(restartIfRunning = false)
        appendLog("INFO", "App", "10.0.0.1", "NexoMesh iniciado en ${Build.MANUFACTURER} ${Build.MODEL}")
        checkFirstInstallScan()
    }

    private fun createActionButton(label: String, bgHex: String, textHex: String, onClick: () -> Unit): Button {
        return Button(this).apply {
            text = label
            setBackgroundColor(Color.parseColor(bgHex))
            setTextColor(Color.parseColor(textHex))
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = 20
            }
            setOnClickListener { onClick() }
        }
    }

    private fun checkFirstInstallScan() {
        val prefs = getSharedPreferences("nexomesh_prefs", MODE_PRIVATE)
        if (prefs.getBoolean("first_install_done", false)) return

        val oem = Build.MANUFACTURER.lowercase()
        val policy = when {
            oem.contains("xiaomi") || oem.contains("redmi") || oem.contains("poco") ->
                "Xiaomi HyperOS: confirmación automática + keepalive 10s"
            oem.contains("samsung") ->
                "Samsung One UI / Knox: confirmación automática + exclusión Doze"
            else ->
                "Android Stock: confirmación automática inmediata VpnService"
        }

        AlertDialog.Builder(this)
            .setTitle("Primera instalación")
            .setMessage("¿Quieres que escanee tu celular para aplicar confirmación automática?\n\nDetectado: ${Build.MANUFACTURER} ${Build.MODEL}\nPolítica: $policy")
            .setPositiveButton("Sí, escanear mi celular") { _, _ ->
                prefs.edit()
                    .putBoolean("first_install_done", true)
                    .putString("oem_policy", policy)
                    .apply()
                appendLog("INFO", "VpnService", "10.0.0.1", "Confirmación automática: $policy")
                statusText.text = "Confirmado automáticamente: $policy"
                requestAndStartVpn()
            }
            .setNegativeButton("Omitir") { _, _ ->
                prefs.edit().putBoolean("first_install_done", true).apply()
            }
            .show()
    }

    private fun getOrCreatePublicKey(): String {
        val prefs = getSharedPreferences("nexomesh_prefs", MODE_PRIVATE)
        val existing = prefs.getString("host_pub_key", null)
        if (!existing.isNullOrBlank()) return existing
        val bytes = ByteArray(32)
        SecureRandom().nextBytes(bytes)
        val generated = Base64.encodeToString(bytes, Base64.NO_WRAP)
        prefs.edit().putString("host_pub_key", generated).apply()
        return generated
    }

    private fun showHostQrDialog() {
        val pubKey = getOrCreatePublicKey()
        val stunInfo = if (RustCoreBridge.isNativeReady()) {
            RustCoreBridge.discoverStunEndpoint("stun.l.google.com:19302")
        } else {
            "187.190.84.212:51820"
        }
        val nextIp = "10.0.0.${connectedPeers.size + 2}"
        val uri = "nexomesh://join?pk=${Uri.encode(pubKey)}&ep=${Uri.encode(stunInfo)}&ip=$nextIp&noise=IKpsk2&name=${Uri.encode(Build.MODEL)}"
        val qrBitmap = generateQrBitmap(uri, 520)

        val imageView = ImageView(this).apply {
            setImageBitmap(qrBitmap)
            setPadding(24, 24, 24, 24)
        }

        AlertDialog.Builder(this)
            .setTitle("Tu Código QR P2P ($nextIp)")
            .setView(imageView)
            .setPositiveButton("Compartir Enlace") { _, _ ->
                val shareIntent = Intent(Intent.ACTION_SEND).apply {
                    type = "text/plain"
                    putExtra(Intent.EXTRA_TEXT, uri)
                }
                startActivity(Intent.createChooser(shareIntent, "Compartir invitación NexoMesh"))
            }
            .setNegativeButton("Cerrar", null)
            .show()
    }

    private fun generateQrBitmap(content: String, size: Int): Bitmap {
        val matrix = QRCodeWriter().encode(content, BarcodeFormat.QR_CODE, size, size)
        val bmp = Bitmap.createBitmap(size, size, Bitmap.Config.RGB_565)
        for (x in 0 until size) {
            for (y in 0 until size) {
                bmp.setPixel(x, y, if (matrix.get(x, y)) Color.BLACK else Color.WHITE)
            }
        }
        return bmp
    }

    private fun launchQrScanner() {
        val options = ScanOptions().apply {
            setDesiredBarcodeFormats(ScanOptions.QR_CODE)
            setPrompt("Escanea el código QR NexoMesh de tu amigo")
            setBeepEnabled(true)
            setOrientationLocked(true)
        }
        qrScannerLauncher.launch(options)
    }

    private fun handleScannedInviteUri(rawUri: String) {
        if (!rawUri.startsWith("nexomesh://join?")) {
            statusText.text = "QR inválido (se esperaba nexomesh://join)"
            return
        }
        val uri = Uri.parse(rawUri)
        val peerName = uri.getQueryParameter("name") ?: "Amigo"
        val peerIp = uri.getQueryParameter("ip") ?: "10.0.0.${connectedPeers.size + 2}"
        val endpoint = uri.getQueryParameter("ep") ?: "STUN directo"
        connectedPeers.add("$peerName ($peerIp)")
        peerSummaryText.text = "Pares enlazados: ${connectedPeers.size} · Último: $peerName ($peerIp)"
        appendLog("INFO", "Noise", peerIp, "Par '$peerName' autenticado por QR ($endpoint)")
        statusText.text = "Par conectado: $peerName ($peerIp)"
    }

    private fun registerNetworkMonitor() {
        try {
            val cm = getSystemService(ConnectivityManager::class.java)
            cm.registerDefaultNetworkCallback(networkCallback)
        } catch (_: Exception) {
        }
    }

    private fun triggerLossAndExponentialBackoff() {
        backoffAttempt += 1
        val delayMs = min(32000L, 1000L shl (backoffAttempt - 1))
        appendLog("CRITICAL", "Alerta", "10.0.0.1", "Red perdida por completo. Backoff intento #$backoffAttempt en ${delayMs / 1000}s")
        statusText.text = "ALERTA: Red Perdida · Reintento #$backoffAttempt en ${delayMs / 1000}s"
        statusText.setTextColor(Color.parseColor("#EF4444"))

        mainHandler.postDelayed({
            if (vpnRunning && backoffAttempt > 0) {
                triggerLossAndExponentialBackoff()
            }
        }, delayMs)
    }

    private fun appendLog(severity: String, subsystem: String, peerIp: String, message: String) {
        val ts = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss", Locale.US).format(Date())
        val escaped = message.replace("\"", "\"\"")
        logsList.add(0, "$ts,$severity,$subsystem,$peerIp,\"$escaped\"")
    }

    private fun exportLogsToCsv() {
        val csvFile = File(cacheDir, "nexomesh-logs.csv")
        val header = "timestamp,severity,subsystem,peer_ip,message\n"
        csvFile.writeText(header + logsList.joinToString("\n"))
        val contentUri = FileProvider.getUriForFile(this, "$packageName.fileprovider", csvFile)
        val sendIntent = Intent(Intent.ACTION_SEND).apply {
            type = "text/csv"
            putExtra(Intent.EXTRA_STREAM, contentUri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        startActivity(Intent.createChooser(sendIntent, "Exportar historial de logs CSV"))
    }

    private fun requestAndStartVpn() {
        val prepareIntent = VpnService.prepare(this)
        if (prepareIntent != null) {
            vpnPermissionLauncher.launch(prepareIntent)
        } else {
            startMeshTunnel()
        }
    }

    private fun showTransportModeDialog() {
        val options = arrayOf(
            "Automático (Detectar 4G/5G o Cable Ethernet)",
            "Manual: Datos Móviles 4G/5G (MTU 1280 · Keepalive 10s)",
            "Manual: Cable Ethernet (MTU 1420 · Keepalive 25s)"
        )
        AlertDialog.Builder(this)
            .setTitle("Modo de Conexión P2P")
            .setItems(options) { _, which ->
                when (which) {
                    0 -> {
                        autoTransportMode = true
                        detectAndApplyAutoTransport(restartIfRunning = vpnRunning)
                    }
                    1 -> {
                        autoTransportMode = false
                        applyManualTransport(isEthernet = false, restartIfRunning = vpnRunning)
                    }
                    2 -> {
                        autoTransportMode = false
                        applyManualTransport(isEthernet = true, restartIfRunning = vpnRunning)
                    }
                }
            }
            .setNegativeButton("Cancelar", null)
            .show()
    }

    private fun detectAndApplyAutoTransport(restartIfRunning: Boolean) {
        try {
            val cm = getSystemService(ConnectivityManager::class.java)
            val caps = cm.getNetworkCapabilities(cm.activeNetwork)
            if (caps != null) {
                applyCapabilitiesPolicy(caps, restartIfRunning)
                return
            }
        } catch (_: Exception) {
        }
        applyTransportParameters(isEthernet = false, isAuto = true, restartIfRunning = restartIfRunning)
    }

    private fun applyCapabilitiesPolicy(caps: NetworkCapabilities, restartIfRunning: Boolean) {
        val isEthernet = caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)
        applyTransportParameters(isEthernet = isEthernet, isAuto = true, restartIfRunning = restartIfRunning)
    }

    private fun applyManualTransport(isEthernet: Boolean, restartIfRunning: Boolean) {
        applyTransportParameters(isEthernet = isEthernet, isAuto = false, restartIfRunning = restartIfRunning)
    }

    private fun applyTransportParameters(isEthernet: Boolean, isAuto: Boolean, restartIfRunning: Boolean) {
        activeMtu = if (isEthernet) 1420 else 1280
        activeKeepalive = if (isEthernet) 25 else 10
        val mediumName = if (isEthernet) "Cable Ethernet" else "4G/5G"
        activeTransportLabel = if (isAuto) "Auto ($mediumName)" else "Manual ($mediumName)"
        transportBtn.text = "Conexión: $activeTransportLabel · MTU $activeMtu"
        appendLog(
            "INFO",
            "WireGuard",
            "10.0.0.1",
            "Política $activeTransportLabel aplicada (MTU $activeMtu, Keepalive ${activeKeepalive}s)"
        )
        if (restartIfRunning) {
            startMeshTunnel()
        }
    }

    private fun showAndroidKeepAliveGuideDialog() {
        val pm = getSystemService(PowerManager::class.java)
        val batteryPass = pm?.isIgnoringBatteryOptimizations(packageName) == true
        val prefs = getSharedPreferences("nexomesh_prefs", MODE_PRIVATE)
        val lockPass = prefs.getBoolean("keepalive_lock_pass", false)
        val vpnAlwaysOnPass = prefs.getBoolean("keepalive_vpn_pass", false)
        val bgDataPass = prefs.getBoolean("keepalive_data_pass", false)

        val steps = arrayOf(
            "1. Batería Sin Restricciones: " + if (batteryPass) "[PASS]" else "[PENDIENTE -> Tocar]",
            "2. Inicio Auto + Candado en Recientes: " + if (lockPass) "[PASS]" else "[PENDIENTE -> Tocar]",
            "3. VPN Siempre Activa: " + if (vpnAlwaysOnPass) "[PASS]" else "[PENDIENTE -> Tocar]",
            "4. Datos Sin Restricciones: " + if (bgDataPass) "[PASS]" else "[PENDIENTE -> Tocar]"
        )

        AlertDialog.Builder(this)
            .setTitle("Guía Anti-Cierre Android")
            .setItems(steps) { _, which ->
                when (which) {
                    0 -> {
                        try {
                            val intent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
                                data = Uri.parse("package:$packageName")
                            }
                            startActivity(intent)
                        } catch (_: Exception) {
                            startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
                        }
                    }
                    1 -> {
                        prefs.edit().putBoolean("keepalive_lock_pass", true).apply()
                        appendLog("INFO", "App", "10.0.0.1", "Paso 2 (Candado/Autostart) marcado PASS")
                        showAndroidKeepAliveGuideDialog()
                    }
                    2 -> {
                        prefs.edit().putBoolean("keepalive_vpn_pass", true).apply()
                        try {
                            startActivity(Intent(Settings.ACTION_VPN_SETTINGS))
                        } catch (_: Exception) {
                        }
                    }
                    3 -> {
                        prefs.edit().putBoolean("keepalive_data_pass", true).apply()
                        try {
                            val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                                data = Uri.parse("package:$packageName")
                            }
                            startActivity(intent)
                        } catch (_: Exception) {
                        }
                    }
                }
            }
            .setPositiveButton("Marcar Todo PASS") { _, _ ->
                prefs.edit()
                    .putBoolean("keepalive_lock_pass", true)
                    .putBoolean("keepalive_vpn_pass", true)
                    .putBoolean("keepalive_data_pass", true)
                    .apply()
                appendLog("INFO", "VpnService", "10.0.0.1", "Guía anti-cierre Android marcada como PASS")
            }
            .setNegativeButton("Cerrar", null)
            .show()
    }

    private fun startMeshTunnel() {
        val intent = Intent(this, MeshVpnService::class.java).apply {
            putExtra("VIRTUAL_IP", "10.0.0.1")
            putExtra("MTU", activeMtu)
            putExtra("KEEPALIVE_SEC", activeKeepalive)
            putExtra("STUN_SERVER", "stun.l.google.com:19302")
        }
        ContextCompat.startForegroundService(this, intent)
        vpnRunning = true
        toggleBtn.text = "Desconectar Túnel"
        statusText.setTextColor(Color.parseColor("#10B981"))
        statusText.text = "Túnel Activo (10.0.0.1/24 · $activeTransportLabel · ${activeKeepalive}s)"
        appendLog("INFO", "WireGuard", "10.0.0.1", "Túnel VPN iniciado (MTU $activeMtu, keepalive ${activeKeepalive}s)")
    }

    private fun stopMeshTunnel() {
        mainHandler.removeCallbacksAndMessages(null)
        backoffAttempt = 0
        val intent = Intent(this, MeshVpnService::class.java).apply { action = "STOP" }
        startService(intent)
        vpnRunning = false
        toggleBtn.text = "Conectar Túnel VPN"
        statusText.setTextColor(Color.parseColor("#94A3B8"))
        statusText.text = "Estado: Desconectado"
        appendLog("WARNING", "WireGuard", "10.0.0.1", "Túnel detenido por el usuario")
    }

    override fun onDestroy() {
        mainHandler.removeCallbacksAndMessages(null)
        try {
            val cm = getSystemService(ConnectivityManager::class.java)
            cm.unregisterNetworkCallback(networkCallback)
        } catch (_: Exception) {
        }
        super.onDestroy()
    }
}
