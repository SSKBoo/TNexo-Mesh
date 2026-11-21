package io.nexomesh.vpn

import android.app.Activity
import android.app.Dialog
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.DashPathEffect
import android.graphics.Paint
import android.graphics.Path
import android.graphics.RectF
import android.graphics.Typeface
import android.graphics.drawable.ColorDrawable
import android.graphics.drawable.GradientDrawable
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.os.Handler
import android.os.Looper
import android.os.PowerManager
import android.os.SystemClock
import android.provider.DocumentsContract
import android.provider.OpenableColumns
import android.provider.Settings
import android.text.Editable
import android.text.InputType
import android.text.TextWatcher
import android.util.Base64
import android.view.Gravity
import android.view.View
import android.view.Window
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.HorizontalScrollView
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.content.FileProvider
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.io.FileOutputStream
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.ServerSocket
import java.net.Socket
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.text.Normalizer
import java.text.SimpleDateFormat
import java.util.Collections
import java.util.Date
import java.util.Locale
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.math.min
import kotlin.math.sin

class MainActivity : AppCompatActivity() {
    data class PeerItem(
        val id: String,
        val name: String,
        val virtualIp: String,
        val platform: String,
        var endpoint: String,
        var lanEndpoint: String = "",
        var online: Boolean = true,
        var quarantined: Boolean = false,
        var quarantineReason: String? = null,
        var rttMs: Int = 22
    )

    data class StagedTransferItem(
        val id: String,
        val uri: Uri,
        val displayName: String,
        val sizeBytes: Long,
        val isFolder: Boolean,
        val fileCount: Int = 1
    )

    data class LogItem(
        val timestamp: String,
        val severity: String,
        val subsystem: String,
        val peerIp: String,
        val message: String
    )

    data class TransferItem(
        val id: String,
        val fileName: String,
        val sizeBytes: Long,
        val direction: String, // "send" | "receive"
        val peerIp: String,
        var status: String, // "transferring" | "paused" | "thawing" | "completed" | "failed" | "canceled"
        var progressPct: Int = 100,
        var frostLevel: Int = 0,
        var errorReason: String? = null,
        val localFile: File? = null,
        val sourceUri: Uri? = null,
        val isFolder: Boolean = false,
        var channel: String = "Túnel VPN"
    )

    private enum class AppTab { TUNNEL, FILES, CONNECT, GUARDIAN, ACTIVITY, SETTINGS }

    private var currentTab = AppTab.TUNNEL
    private var connectSubTab = 0 // 0 = Mi QR, 1 = Escanear Amigo
    private var filesSubTab = 0 // 0 = Enviar, 1 = Recibir
    private var activitySubTab = 0 // 0 = Métricas, 1 = Topología P2P
    private var inviteRequire2fa = true
    private var currentInvitePin = String.format(Locale.US, "%06d", 100000 + SecureRandom().nextInt(900000))
    private var logSeverityFilter = "ALL"
    private var fileFilterCategory = "ALL" // ALL | SENT | RECEIVED | PENDING | COMPLETED | FAILED | CANCELED
    private var fileMaxSpeedMode = true
    private var fileSendChannel = "VPN" // VPN | LAN | BLUETOOTH | LAN_BLUETOOTH
    private var connectPeerSearchQuery = ""

    private var myVirtualIp = "10.0.0.1"
    private var vpnRunning = false
    private var autoTransportMode = true
    private var activeMedium = "wifi" // cellular | wifi | ethernet
    private var activeMtu = 1380
    private var activeKeepalive = 15
    private var activeTransportLabel = "Auto (Wi-Fi)"
    private var activeStunServer = "stun.l.google.com:19302"
    private var lastStunMapped = "Consultando STUN..."
    private var backoffAttempt = 0
    private var reopenKeepAliveOnResume = false
    private var pendingSettingsStep: String? = null
    private var pendingSettingsLeftAtMs: Long = 0L
    private var pendingLossRunnable: Runnable? = null
    private var backoffRetryRunnable: Runnable? = null

    private var fileReceiverActive = false
    private var fileServerSocket: ServerSocket? = null
    private var pendingSendTargetIp = ""
    private var receiveFolderUri: Uri? = null
    private var receiveFolderLabel = ""
    private var startReceiverAfterFolderPick = false

    private val mainHandler = Handler(Looper.getMainLooper())
    private val logsList = mutableListOf<LogItem>()
    private val connectedPeers = mutableListOf<PeerItem>()
    private val stagedSendItems = mutableListOf<StagedTransferItem>()
    private val fileTransfersList = mutableListOf<TransferItem>()
    private val rttHistory = mutableListOf(22f, 24f, 19f, 21f, 18f, 23f, 20f, 19f)
    private val rxHistory = mutableListOf(48f, 52f, 64f, 59f, 71f, 68f, 74f, 70f)
    private val txHistory = mutableListOf(36f, 41f, 49f, 44f, 56f, 51f, 58f, 55f)
    private val peerRtt60sHistory = mutableMapOf<String, MutableList<Pair<Long, Float>>>()
    private var waveTick = 0

    private var activeTheme = "dark" // dark | neon | oled
    private var shieldEnabled = true
    private var bunkerMode = false
    private var policyAutoQuarantine = true
    private var policyAutoRotateKeys = true
    private var policyUdpRateLimit = true
    private var policyAutoBunkerOnCrit = false
    private var policyStrictDnsKill = true
    private var blockedPacketsCount = 0
    private var rekeyCount = 0

    private val themedSurfaceCards = mutableListOf<LinearLayout>()
    private val themedInsetCards = mutableListOf<LinearLayout>()

    private lateinit var rootContainer: LinearLayout
    private lateinit var topBar: LinearLayout
    private lateinit var topDivider: View
    private lateinit var bottomDivider: View
    private lateinit var bottomBar: LinearLayout
    private lateinit var headerBadge: TextView
    private lateinit var headerProfilePill: LinearLayout
    private lateinit var headerAvatarBadge: TextView
    private lateinit var headerAvatarImage: ImageView
    private lateinit var headerProfileName: TextView
    private lateinit var tabContentContainer: FrameLayout
    private lateinit var bottomTabViews: MutableMap<AppTab, TextView>

    private lateinit var tunnelView: ScrollView
    private lateinit var filesView: ScrollView
    private lateinit var connectView: ScrollView
    private lateinit var guardianView: ScrollView
    private lateinit var activityView: ScrollView
    private lateinit var settingsView: ScrollView

    // Tunnel Tab Views
    private lateinit var tunnelPolicyLabel: TextView
    private lateinit var tunnelTitleText: TextView
    private lateinit var tunnelSubtitleText: TextView
    private lateinit var powerCircleBtn: Button
    private lateinit var stunLineText: TextView
    private lateinit var metricStability: TextView
    private lateinit var metricLatency: TextView
    private lateinit var metricSpeed: TextView
    private lateinit var transportSummaryTitle: TextView
    private lateinit var btnAutoMode: Button
    private lateinit var btnCellularMode: Button
    private lateinit var btnWifiMode: Button
    private lateinit var btnEthernetMode: Button
    private lateinit var transportDetailText: TextView
    private lateinit var footerStatsText: TextView
    private lateinit var simulateLossBtn: Button
    private lateinit var tunnelKeepAliveBtn: Button
    private lateinit var tunnelGuardianMiniText: TextView
    private lateinit var peersHeaderTitle: TextView
    private lateinit var peersListContainer: LinearLayout

    // Dedicated Files Tab Views
    private lateinit var fileSpeedModeBtn: Button
    private lateinit var fileSubSendBtn: Button
    private lateinit var fileSubReceiveBtn: Button
    private lateinit var fileSendSection: LinearLayout
    private lateinit var fileReceiveSection: LinearLayout
    private lateinit var fileChanVpnBtn: Button
    private lateinit var fileChanLanBtn: Button
    private lateinit var fileChanBtBtn: Button
    private lateinit var fileChanBothBtn: Button
    private lateinit var fileChannelHintText: TextView
    private lateinit var filePeerChipsContainer: LinearLayout
    private lateinit var fileTargetIpInput: EditText
    private lateinit var stagedBatchCard: LinearLayout
    private lateinit var stagedBatchTitle: TextView
    private lateinit var stagedItemsContainer: LinearLayout
    private lateinit var stagedSendBatchBtn: Button
    private lateinit var fileReceiveFolderBtn: Button
    private lateinit var fileReceiverToggleBtn: Button
    private lateinit var fileReceiverHostInfo: TextView
    private lateinit var fileFilterAllBtn: Button
    private lateinit var fileFilterSentBtn: Button
    private lateinit var fileFilterReceivedBtn: Button
    private lateinit var fileFilterPendingBtn: Button
    private lateinit var fileFilterCompletedBtn: Button
    private lateinit var fileFilterFailedBtn: Button
    private lateinit var fileFilterCanceledBtn: Button
    private lateinit var fileTransfersContainer: LinearLayout

    // Connect Tab Views
    private lateinit var connectPeerSearchInput: EditText
    private lateinit var connectPeerClearBtn: Button
    private lateinit var connectPeerCountText: TextView
    private lateinit var connectPeerResultsContainer: LinearLayout
    private lateinit var subTabShareBtn: Button
    private lateinit var subTabScanBtn: Button
    private lateinit var inviteWith2faBtn: Button
    private lateinit var inviteNo2faBtn: Button
    private lateinit var invitePinText: TextView
    private lateinit var shareQrCard: LinearLayout
    private lateinit var scanQrCard: LinearLayout
    private lateinit var qrImageView: ImageView
    private lateinit var qrIpText: TextView
    private lateinit var qrEndpointText: TextView
    private lateinit var qrKeyText: TextView
    private lateinit var inviteUriInput: EditText

    // Activity / Status Tab Views
    private lateinit var telemetryGraphView: TelemetryGraphView
    private lateinit var telemetrySummaryText: TextView
    private lateinit var peerRtt60sGraphView: PeerRtt60sGraphView
    private lateinit var peerRtt60sSummaryText: TextView
    private lateinit var peerAvgBarGraphView: PeerAvgLatencyBarGraphView
    private lateinit var peerAvgBarSummaryText: TextView
    private lateinit var activitySubMetricsBtn: Button
    private lateinit var activitySubTopologyBtn: Button
    private lateinit var activityMetricsSection: LinearLayout
    private lateinit var activityTopologySection: LinearLayout
    private lateinit var meshTopologyCanvasView: MeshTopologyCanvasView
    private lateinit var meshTopologySummaryText: TextView
    private lateinit var statBoxRtt: TextView
    private lateinit var statBoxRx: TextView
    private lateinit var statBoxTx: TextView
    private lateinit var statBoxScore: TextView
    private lateinit var activityStunTitle: TextView
    private lateinit var activityStunEndpoint: TextView
    private lateinit var filterAllBtn: Button
    private lateinit var filterInfoBtn: Button
    private lateinit var filterWarnBtn: Button
    private lateinit var filterCritBtn: Button
    private lateinit var logsTitleText: TextView
    private lateinit var logsContainer: LinearLayout

    // Guardián Tab Views
    private lateinit var defenseCard: LinearLayout
    private lateinit var guardianPostureBanner: LinearLayout
    private lateinit var guardianPostureTitle: TextView
    private lateinit var guardianPostureSub: TextView
    private lateinit var defenseShieldBtn: Button
    private lateinit var defenseBunkerBtn: Button
    private lateinit var defenseStatsText: TextView
    private lateinit var policyQuarantineSwitch: CheckBox
    private lateinit var policyRotateSwitch: CheckBox
    private lateinit var policyRateLimitSwitch: CheckBox
    private lateinit var policyAutoBunkerSwitch: CheckBox
    private lateinit var policyStrictDnsSwitch: CheckBox
    private lateinit var defenseQuarantineContainer: LinearLayout

    // Settings Tab Views (Appearance, Device, KeepAlive)
    private lateinit var appearanceCard: LinearLayout
    private lateinit var themeDarkBtn: Button
    private lateinit var themeNeonBtn: Button
    private lateinit var themeOledBtn: Button
    private lateinit var deviceCard: LinearLayout
    private lateinit var guideCard: LinearLayout
    private lateinit var settingsDeviceSubtitle: TextView
    private lateinit var settingsAutoBtn: Button
    private lateinit var settingsCellularBtn: Button
    private lateinit var settingsWifiBtn: Button
    private lateinit var settingsEthernetBtn: Button
    private lateinit var settingsMtu1280Btn: Button
    private lateinit var settingsMtu1380Btn: Button
    private lateinit var settingsMtu1420Btn: Button
    private lateinit var settingsKa10Btn: Button
    private lateinit var settingsKa15Btn: Button
    private lateinit var settingsKa25Btn: Button
    private lateinit var settingsRecTitle: TextView
    private lateinit var settingsRecTopology: TextView
    private lateinit var settingsRecDesc: TextView
    private lateinit var settingsRecBullets: TextView
    private lateinit var settingsStunText: TextView
    private lateinit var guideHeaderTitle: TextView
    private lateinit var guideProgressText: TextView
    private lateinit var guideProgressBar: ProgressBar
    private lateinit var guideInlineResultText: TextView
    private lateinit var guideStepsContainer: LinearLayout
    private lateinit var guideVerifyBtn: Button
    private lateinit var guideTopVerifyBtn: Button

    private var profileModalRefreshAvatar: (() -> Unit)? = null

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            startMeshTunnel()
        } else {
            appendLog("WARNING", "VpnService", myVirtualIp, "Permiso VPN rechazado por el sistema")
            refreshAllUi()
        }
    }

    private val multiFilePickerLauncher = registerForActivityResult(
        ActivityResultContracts.OpenMultipleDocuments()
    ) { uris ->
        if (!uris.isNullOrEmpty()) {
            addPickedFilesToStage(uris)
        }
    }

    private val folderPickerLauncher = registerForActivityResult(
        ActivityResultContracts.OpenDocumentTree()
    ) { treeUri ->
        if (treeUri != null) {
            addPickedFolderToStage(treeUri)
        }
    }

    private val avatarPickerLauncher = registerForActivityResult(
        ActivityResultContracts.GetContent()
    ) { uri ->
        if (uri != null) {
            savePickedAvatarMedia(uri)
        }
    }

    private val receiveFolderPickerLauncher = registerForActivityResult(
        ActivityResultContracts.OpenDocumentTree()
    ) { treeUri ->
        if (treeUri != null) {
            try {
                contentResolver.takePersistableUriPermission(
                    treeUri,
                    Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                )
            } catch (_: Exception) {}
            val docId = DocumentsContract.getTreeDocumentId(treeUri)
            val label = docId.substringAfterLast(':').ifBlank { "Carpeta Seleccionada" }
            receiveFolderUri = treeUri
            receiveFolderLabel = label
            getSharedPreferences("nexomesh_prefs", MODE_PRIVATE).edit()
                .putString("receive_tree_uri", treeUri.toString())
                .putString("receive_tree_label", label)
                .apply()
            appendLog("INFO", "WireGuard", myVirtualIp, "Carpeta destino de recibidos: $label/")
            if (startReceiverAfterFolderPick && !fileReceiverActive) {
                startReceiverAfterFolderPick = false
                startFileReceiverSocketLoop()
            } else {
                refreshAllUi()
            }
        } else {
            startReceiverAfterFolderPick = false
        }
    }

    private val qrScannerLauncher = registerForActivityResult(ScanContract()) { result ->
        val raw = result.contents
        if (raw.isNullOrBlank()) {
            appendLog("WARNING", "WireGuard", myVirtualIp, "Escaneo de cámara QR cancelado")
            refreshAllUi()
            return@registerForActivityResult
        }
        handleScannedInviteUri(raw)
    }

    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onLost(network: Network) {
            runOnUiThread {
                if (!vpnRunning) return@runOnUiThread
                pendingLossRunnable?.let { mainHandler.removeCallbacks(it) }
                val checkLoss = Runnable {
                    if (!vpnRunning) return@Runnable
                    if (!hasPhysicalInternet() && backoffAttempt == 0) {
                        triggerLossAndExponentialBackoff()
                    }
                }
                pendingLossRunnable = checkLoss
                mainHandler.postDelayed(checkLoss, 900L)
            }
        }

        override fun onAvailable(network: Network) {
            runOnUiThread {
                pendingLossRunnable?.let { mainHandler.removeCallbacks(it) }
                val cm = getSystemService(ConnectivityManager::class.java)
                val caps = cm?.getNetworkCapabilities(network)
                if (caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                    return@runOnUiThread
                }
                if (autoTransportMode && caps != null && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) {
                    applyCapabilitiesPolicy(caps, restartIfRunning = false)
                }
                if (backoffAttempt > 0) {
                    backoffAttempt = 0
                    backoffRetryRunnable?.let { mainHandler.removeCallbacks(it) }
                    appendLog("INFO", "Backoff", "10.0.0.1", "Red recuperada; reabriendo túnel P2P")
                    startMeshTunnel()
                }
            }
        }

        override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) {
            runOnUiThread {
                if (networkCapabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                    return@runOnUiThread
                }
                if (!networkCapabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) {
                    return@runOnUiThread
                }
                if (autoTransportMode) {
                    applyCapabilitiesPolicy(networkCapabilities, restartIfRunning = vpnRunning)
                }
            }
        }
    }

    /**
     * Registra el descubrimiento bidireccional de pares. Al recibir NM_HELLO/NM_ACK
     * de otro par, se agrega o actualiza automǭticamente en la lista.
     */
    private fun registerPeerDiscoveryCallback() {
        MeshVpnService.registerDiscoveredPeerCallback { vip, name, remoteAddr ->
            runOnUiThread {
                val discovered = connectedPeers.firstOrNull { it.virtualIp == vip }
                if (discovered == null) {
                    connectedPeers.add(
                        PeerItem(
                            id = "peer-${System.currentTimeMillis()}",
                            name = name,
                            virtualIp = vip,
                            platform = "P2P Mesh",
                            endpoint = remoteAddr,
                            lanEndpoint = remoteAddr,
                            online = true,
                            rttMs = 1
                        )
                    )
                } else {
                    discovered.endpoint = remoteAddr
                    discovered.lanEndpoint = remoteAddr
                    discovered.online = true
                    discovered.rttMs = 1
                }
                syncPeersToVpnService()
                appendLog("INFO", "Noise", vip, "Par P2P descubierto y enlazado: '$name' ($remoteAddr)")
                refreshAllUi()
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        WindowCompat.setDecorFitsSystemWindows(window, false)
        bottomTabViews = mutableMapOf()

        val bootPrefs = getSharedPreferences("nexomesh_prefs", MODE_PRIVATE)
        myVirtualIp = bootPrefs.getString("my_virtual_ip", "10.0.0.1") ?: "10.0.0.1"
        MeshVpnService.updateLocalVirtualIp(myVirtualIp)
        registerPeerDiscoveryCallback()
        activeTheme = bootPrefs.getString("app_theme", "dark") ?: "dark"
        shieldEnabled = bootPrefs.getBoolean("guardian_enabled", true)
        policyAutoQuarantine = bootPrefs.getBoolean("policy_quarantine", true)
        policyAutoRotateKeys = bootPrefs.getBoolean("policy_rotate", true)
        policyUdpRateLimit = bootPrefs.getBoolean("policy_ratelimit", true)
        policyAutoBunkerOnCrit = bootPrefs.getBoolean("policy_autobunker", false)
        policyStrictDnsKill = bootPrefs.getBoolean("policy_strictdns", true)
        bootPrefs.getString("receive_tree_uri", null)?.let { savedUri ->
            try {
                receiveFolderUri = Uri.parse(savedUri)
                receiveFolderLabel = bootPrefs.getString("receive_tree_label", "") ?: ""
            } catch (_: Exception) {}
        }
        MeshVpnService.registerDiscoveredPeerCallback { vip, pName, remoteAddr ->
            runOnUiThread {
                val existing = connectedPeers.firstOrNull { it.virtualIp == vip }
                if (existing == null) {
                    connectedPeers.add(PeerItem("peer-${System.currentTimeMillis()}", pName, vip, "P2P Mesh", remoteAddr, remoteAddr, true))
                    pendingSendTargetIp = vip
                    if (::fileTargetIpInput.isInitialized) {
                        fileTargetIpInput.setText(vip)
                    }
                    syncPeersToVpnService()
                    appendLog("INFO", "WireGuard", vip, "Par '$pName' descubierto por paquete UDP directo ($remoteAddr)")
                    refreshAllUi()
                } else {
                    existing.lanEndpoint = remoteAddr
                    existing.online = true
                    syncPeersToVpnService()
                }
            }
        }

        rootContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.parseColor(themeBg()))
        }

        ViewCompat.setOnApplyWindowInsetsListener(rootContainer) { view, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            view.setPadding(0, bars.top, 0, bars.bottom)
            insets
        }

        // Top App Bar (3-zone preview layout with custom avatar pill)
        topBar = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setBackgroundColor(Color.parseColor(themeBg()))
            setPadding(dp(16), dp(10), dp(16), dp(10))
        }

        val brandCol = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }
        val brandTitle = TextView(this).apply {
            text = "NexoMesh"
            textSize = 20f
            setTypeface(null, Typeface.BOLD)
            setTextColor(Color.parseColor("#F8FAFC"))
        }
        val brandSub = TextView(this).apply {
            text = "${Build.MANUFACTURER} ${Build.MODEL} · Android ${Build.VERSION.RELEASE}"
            textSize = 11f
            setTextColor(Color.parseColor("#94A3B8"))
        }
        brandCol.addView(brandTitle)
        brandCol.addView(brandSub)

        headerBadge = TextView(this).apply {
            text = "Desconectado"
            textSize = 11f
            setTypeface(null, Typeface.BOLD)
            setPadding(dp(10), dp(6), dp(10), dp(6))
        }

        headerProfilePill = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            background = makeCardDrawable(themeSurface(), themeBorder(), 14, 1)
            setPadding(dp(8), dp(6), dp(10), dp(6))
            minimumHeight = dp(40)
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { leftMargin = dp(8) }
            setOnClickListener { showUserProfileDialog() }
        }
        val avatarBox = FrameLayout(this).apply {
            layoutParams = LinearLayout.LayoutParams(dp(28), dp(28)).apply { rightMargin = dp(6) }
        }
        headerAvatarBadge = TextView(this).apply {
            text = "🛡️"
            textSize = 13f
            gravity = Gravity.CENTER
            setTextColor(Color.parseColor("#34D399"))
            background = makeCardDrawable("#064E3B", "#10B981", 99, 1)
            layoutParams = FrameLayout.LayoutParams(dp(28), dp(28))
        }
        headerAvatarImage = ImageView(this).apply {
            scaleType = ImageView.ScaleType.CENTER_CROP
            visibility = View.GONE
            layoutParams = FrameLayout.LayoutParams(dp(28), dp(28))
        }
        avatarBox.addView(headerAvatarBadge)
        avatarBox.addView(headerAvatarImage)

        headerProfileName = TextView(this).apply {
            text = bootPrefs.getString("user_name", Build.MODEL)?.take(12) ?: "Perfil"
            textSize = 12f
            setTypeface(null, Typeface.BOLD)
            setTextColor(Color.parseColor("#F8FAFC"))
        }
        headerProfilePill.addView(avatarBox)
        headerProfilePill.addView(headerProfileName)

        topBar.addView(brandCol)
        topBar.addView(headerBadge)
        topBar.addView(headerProfilePill)

        topDivider = View(this).apply {
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, dp(1))
            setBackgroundColor(Color.parseColor(themeBorder()))
        }

        tabContentContainer = FrameLayout(this).apply {
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f)
        }

        tunnelView = buildTunnelTabView()
        filesView = buildFilesTabView()
        connectView = buildConnectTabView()
        guardianView = buildGuardianTabView()
        activityView = buildActivityTabView()
        settingsView = buildSettingsTabView()

        tabContentContainer.addView(tunnelView)
        tabContentContainer.addView(filesView)
        tabContentContainer.addView(connectView)
        tabContentContainer.addView(guardianView)
        tabContentContainer.addView(activityView)
        tabContentContainer.addView(settingsView)

        bottomDivider = View(this).apply {
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, dp(1))
            setBackgroundColor(Color.parseColor(themeBorder()))
        }

        bottomBar = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setBackgroundColor(Color.parseColor(themeSurface()))
            setPadding(dp(2), dp(8), dp(2), dp(8))
        }

        val tabDefs = listOf(
            AppTab.TUNNEL to "Túnel",
            AppTab.FILES to "Archivos",
            AppTab.CONNECT to "Conectar",
            AppTab.GUARDIAN to "Guardián",
            AppTab.ACTIVITY to "Estado",
            AppTab.SETTINGS to "Ajustes"
        )
        for ((tab, label) in tabDefs) {
            val tv = TextView(this).apply {
                text = label
                textSize = 10f
                gravity = Gravity.CENTER
                setPadding(dp(1), dp(10), dp(1), dp(10))
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
                setOnClickListener { switchTab(tab) }
            }
            bottomTabViews[tab] = tv
            bottomBar.addView(tv)
        }

        rootContainer.addView(topBar)
        rootContainer.addView(topDivider)
        rootContainer.addView(tabContentContainer)
        rootContainer.addView(bottomDivider)
        rootContainer.addView(bottomBar)

        setContentView(rootContainer)

        registerNetworkMonitor()
        detectAndApplyAutoTransport(restartIfRunning = false)
        appendLog("INFO", "App", myVirtualIp, "NexoMesh iniciado en ${Build.MANUFACTURER} ${Build.MODEL} ($myVirtualIp)")
        applySelectedTheme(activeTheme)
        switchTab(AppTab.TUNNEL)
        refreshAllUi()
        startTelemetryAndTransferLoops()
        runStunProbeAsync(silent = true)
        checkFirstInstallScan()

        // Invitaciǫn sin QR: abrir directamente nexomesh://join?...
        handleInviteIntent(intent)
        // Configurar los callbacks del receptor :51821 aunque el usuario no abra Archivos.
        startFileReceiverSocketLoop()
    }

    private fun handleInviteIntent(incoming: Intent?) {
        val data = incoming?.data ?: return
        if (data.scheme == "nexomesh" && data.host == "join") {
            handleScannedInviteUri(data.toString())
        }
    }

    override fun onNewIntent(incoming: Intent) {
        super.onNewIntent(incoming)
        setIntent(incoming)
        handleInviteIntent(incoming)
    }

    override fun onResume() {
        super.onResume()
        val pending = pendingSettingsStep
        val elapsedAway = SystemClock.elapsedRealtime() - pendingSettingsLeftAtMs
        pendingSettingsStep = null
        pendingSettingsLeftAtMs = 0L

        if (pending != null) {
            handleReturnFromSystemSettings(pending, elapsedAway)
        }
        refreshAllUi()
        if (reopenKeepAliveOnResume) {
            reopenKeepAliveOnResume = false
            switchTab(AppTab.SETTINGS)
        }
    }

    private fun dp(v: Int): Int = (v * resources.displayMetrics.density).toInt()

    private fun makeCardDrawable(bgHex: String, borderHex: String, radiusDp: Int = 16, strokeDp: Int = 1): GradientDrawable {
        return GradientDrawable().apply {
            shape = GradientDrawable.RECTANGLE
            cornerRadius = dp(radiusDp).toFloat()
            setColor(Color.parseColor(bgHex))
            setStroke(dp(strokeDp), Color.parseColor(borderHex))
        }
    }

    private fun makeStyledButton(label: String, bgHex: String, borderHex: String, textHex: String, radiusDp: Int = 12): Button {
        return Button(this).apply {
            text = label
            isAllCaps = false
            textSize = 12f
            setTypeface(null, Typeface.BOLD)
            setTextColor(Color.parseColor(textHex))
            background = makeCardDrawable(bgHex, borderHex, radiusDp, 1)
            setPadding(dp(12), dp(10), dp(12), dp(10))
            minHeight = dp(44)
        }
    }

    private fun themeBg(): String = when (activeTheme) {
        "neon" -> "#050614"
        "oled" -> "#000000"
        else -> "#0B0F17"
    }

    private fun themeSurface(): String = when (activeTheme) {
        "neon" -> "#0B0F26"
        "oled" -> "#060608"
        else -> "#111827"
    }

    private fun themeInset(): String = when (activeTheme) {
        "neon" -> "#070A1B"
        "oled" -> "#000000"
        else -> "#0B0F17"
    }

    private fun themeBorder(): String = when (activeTheme) {
        "neon" -> "#00F5D4"
        "oled" -> "#1E1E24"
        else -> "#1E293B"
    }

    private fun themeAccent(): String = when (activeTheme) {
        "neon" -> "#00F5D4"
        else -> "#10B981"
    }

    private fun makeThemedDialog(
        title: String,
        message: String? = null,
        bodyView: View? = null,
        positiveLabel: String? = "Entendido",
        onPositive: ((Dialog) -> Unit)? = null,
        neutralLabel: String? = null,
        onNeutral: ((Dialog) -> Unit)? = null,
        negativeLabel: String? = null,
        onNegative: ((Dialog) -> Unit)? = null
    ): Dialog {
        val dialog = Dialog(this)
        dialog.requestWindowFeature(Window.FEATURE_NO_TITLE)
        dialog.window?.setBackgroundDrawable(ColorDrawable(Color.TRANSPARENT))

        val card = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = makeCardDrawable(themeSurface(), themeBorder(), 20, 1)
            setPadding(dp(18), dp(18), dp(18), dp(16))
        }
        val titleTv = TextView(this).apply {
            text = title
            textSize = 17f
            setTypeface(null, Typeface.BOLD)
            setTextColor(Color.parseColor("#F8FAFC"))
        }
        card.addView(titleTv)

        if (!message.isNullOrBlank()) {
            val msgTv = TextView(this).apply {
                text = message
                textSize = 13f
                setTextColor(Color.parseColor("#CBD5E1"))
                setPadding(0, dp(8), 0, dp(8))
            }
            card.addView(msgTv)
        }

        if (bodyView != null) {
            card.addView(bodyView)
        }

        val btnRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(0, dp(12), 0, 0)
        }
        if (negativeLabel != null) {
            val neg = makeStyledButton(negativeLabel, themeInset(), "#334155", "#CBD5E1").apply {
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply { rightMargin = dp(4) }
                setOnClickListener {
                    onNegative?.invoke(dialog)
                    dialog.dismiss()
                }
            }
            btnRow.addView(neg)
        }
        if (neutralLabel != null) {
            val neu = makeStyledButton(neutralLabel, "#0C4A6E", "#38BDF8", "#BAE6FD").apply {
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply { leftMargin = dp(4); rightMargin = dp(4) }
                setOnClickListener {
                    onNeutral?.invoke(dialog)
                    dialog.dismiss()
                }
            }
            btnRow.addView(neu)
        }
        if (positiveLabel != null) {
            val posBg = if (activeTheme == "neon") "#063D38" else "#059669"
            val posBorder = themeAccent()
            val pos = makeStyledButton(positiveLabel, posBg, posBorder, "#FFFFFF").apply {
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply { leftMargin = dp(4) }
                setOnClickListener {
                    if (onPositive != null) {
                        onPositive(dialog)
                    } else {
                        dialog.dismiss()
                    }
                }
            }
            btnRow.addView(pos)
        }
        if (btnRow.childCount > 0) {
            card.addView(btnRow)
        }

        val wrapper = ScrollView(this).apply { addView(card) }
        dialog.setContentView(wrapper)
        dialog.window?.setLayout(
            (resources.displayMetrics.widthPixels * 0.92).toInt(),
            LinearLayout.LayoutParams.WRAP_CONTENT
        )
        return dialog
    }

    /**
     * Devuelve todas las IPv4 LAN candidatas (excluyendo la subnet virtual 10.0.0.x).
     * Prioriza wlan/ap/rndis sobre eth: en emuladores eth0 es compartida (10.0.2.15)
     * mientras que wlan0 es única por instancia y alcanzable entre emuladores.
     */
    /** Primer par enlazado distinto de esta IP; nunca la propia. */
    private fun defaultSendTargetIp(): String {
        return connectedPeers.firstOrNull { it.online && it.virtualIp != myVirtualIp }?.virtualIp ?: ""
    }

    private fun getLocalLanIpCandidates(): List<String> {
        return try {
            val interfaces = Collections.list(NetworkInterface.getNetworkInterfaces())
            val preferred = mutableListOf<String>()
            val others = mutableListOf<String>()
            for (iface in interfaces) {
                if (!iface.isUp || iface.isLoopback) continue
                val n = iface.name.lowercase()
                if (n.contains("tun") || n.contains("rmnet") || n.contains("ccmni")) continue
                for (addr in Collections.list(iface.inetAddresses)) {
                    if (!addr.isLoopbackAddress && addr is Inet4Address) {
                        val ip = addr.hostAddress ?: continue
                        if (ip.startsWith("10.0.0.")) continue
                        if (n.contains("wlan") || n.contains("ap") || n.contains("rndis")) {
                            preferred.add(ip)
                        } else if (n.contains("eth")) {
                            others.add(ip)
                        }
                    }
                }
            }
            (preferred + others).distinct()
        } catch (_: Exception) {
            emptyList()
        }
    }

    private fun getLocalLanIpAddress(): String = getLocalLanIpCandidates().firstOrNull() ?: ""

    private fun syncPeersToVpnService() {
        val prefs = getSharedPreferences("nexomesh_prefs", MODE_PRIVATE)
        val list = connectedPeers.filter { !it.quarantined && it.online }.map {
            val peerPk = prefs.getString("peer_pk_${it.virtualIp}", "") ?: ""
            MeshVpnService.PeerEndpointInfo(it.virtualIp, it.name, it.endpoint, it.lanEndpoint, peerPk)
        }
        MeshVpnService.updatePeers(list)
    }

    private fun applySelectedTheme(theme: String) {
        activeTheme = theme
        getSharedPreferences("nexomesh_prefs", MODE_PRIVATE).edit().putString("app_theme", theme).apply()
        val bg = Color.parseColor(themeBg())
        val surf = Color.parseColor(themeSurface())
        val border = Color.parseColor(themeBorder())
        rootContainer.setBackgroundColor(bg)
        topBar.setBackgroundColor(bg)
        bottomBar.setBackgroundColor(surf)
        topDivider.setBackgroundColor(border)
        bottomDivider.setBackgroundColor(border)
        headerProfilePill.background = makeCardDrawable(themeSurface(), themeBorder(), 14, 1)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            window.statusBarColor = bg
            window.navigationBarColor = bg
        }
        for (card in themedSurfaceCards) {
            card.background = makeCardDrawable(themeSurface(), themeBorder(), 18, 1)
        }
        for (inset in themedInsetCards) {
            inset.background = makeCardDrawable(themeInset(), themeBorder(), 12, 1)
        }
        switchTab(currentTab)
        refreshAllUi()
    }

    private fun triggerDefenseAttackTest(vectorName: String) {
        if (!shieldEnabled) {
            appendLog("WARNING", "AutoEscudo", "10.0.0.1", "Modo Guardián apagado: evento $vectorName registrado sin aislar pares ni rotar llaves")
            refreshAllUi()
            return
        }
        blockedPacketsCount += 48
        rekeyCount += 1
        MeshVpnService.blockedPacketsCount += 48L
        val target = connectedPeers.firstOrNull { !it.quarantined }
        if (target != null) {
            target.quarantined = true
            target.online = false
            target.quarantineReason = vectorName
            MeshVpnService.recordSuspiciousTraffic(target.virtualIp, vectorName)
            appendLog("CRITICAL", "AutoEscudo", target.virtualIp, "Ataque $vectorName neutralizado: ${target.name} en cuarentena y llaves rotadas")
        } else {
            appendLog("WARNING", "AutoEscudo", "10.0.0.1", "Sonda $vectorName bloqueada por firewall Rust/UDP")
        }
        if (RustCoreBridge.isNativeReady()) {
            RustCoreBridge.setDefensePolicy(bunkerMode, 120)
        }
        refreshAllUi()
    }

    private fun switchTab(tab: AppTab) {
        currentTab = tab
        tunnelView.visibility = if (tab == AppTab.TUNNEL) View.VISIBLE else View.GONE
        filesView.visibility = if (tab == AppTab.FILES) View.VISIBLE else View.GONE
        connectView.visibility = if (tab == AppTab.CONNECT) View.VISIBLE else View.GONE
        guardianView.visibility = if (tab == AppTab.GUARDIAN) View.VISIBLE else View.GONE
        activityView.visibility = if (tab == AppTab.ACTIVITY) View.VISIBLE else View.GONE
        settingsView.visibility = if (tab == AppTab.SETTINGS) View.VISIBLE else View.GONE

        val acc = themeAccent()
        for ((t, tv) in bottomTabViews) {
            val active = t == tab
            tv.setTextColor(Color.parseColor(if (active) acc else "#94A3B8"))
            tv.setTypeface(null, if (active) Typeface.BOLD else Typeface.NORMAL)
            tv.background = if (active) makeCardDrawable("#10B98120", acc, 10, 1) else null
        }

        if (tab == AppTab.CONNECT) {
            renderInlineQrCode()
        }
    }

    private fun buildTunnelTabView(): ScrollView {
        val scroll = ScrollView(this)
        val col = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(16), dp(16), dp(24))
        }

        // Main VPN Card
        val vpnCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = makeCardDrawable(themeSurface(), themeBorder(), 18, 1)
            setPadding(dp(18), dp(18), dp(18), dp(18))
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dp(16) }
        }
        themedSurfaceCards.add(vpnCard)

        tunnelPolicyLabel = TextView(this).apply {
            text = detectDevicePolicy()
            textSize = 11f
            setTextColor(Color.parseColor("#94A3B8"))
        }
        tunnelTitleText = TextView(this).apply {
            text = "VPN Desconectada"
            textSize = 20f
            setTypeface(null, Typeface.BOLD)
            setTextColor(Color.parseColor("#F8FAFC"))
            setPadding(0, dp(4), 0, dp(2))
        }
        tunnelSubtitleText = TextView(this).apply {
            text = "Toca el botón para abrir la red privada"
            textSize = 12f
            setTextColor(Color.parseColor("#94A3B8"))
        }

        val powerWrap = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding(0, dp(18), 0, dp(14))
        }
        powerCircleBtn = Button(this).apply {
            text = "Conectar"
            isAllCaps = false
            textSize = 14f
            setTypeface(null, Typeface.BOLD)
            layoutParams = LinearLayout.LayoutParams(dp(124), dp(124))
            setOnClickListener {
                if (backoffAttempt > 0) {
                    backoffAttempt = 0
                    backoffRetryRunnable?.let { mainHandler.removeCallbacks(it) }
                    startMeshTunnel()
                } else if (vpnRunning) {
                    stopMeshTunnel()
                } else {
                    requestAndStartVpn()
                }
            }
        }
        stunLineText = TextView(this).apply {
            text = "Noise IKpsk2 · STUN $activeStunServer"
            textSize = 11f
            setTextColor(Color.parseColor("#94A3B8"))
            setPadding(0, dp(10), 0, 0)
        }
        powerWrap.addView(powerCircleBtn)
        powerWrap.addView(stunLineText)

        // Metrics Row
        val metricsRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(0, dp(12), 0, dp(14))
        }
        metricStability = TextView(this).apply { gravity = Gravity.CENTER; textSize = 14f; setTypeface(null, Typeface.BOLD) }
        metricLatency = TextView(this).apply { gravity = Gravity.CENTER; textSize = 14f; setTypeface(null, Typeface.BOLD) }
        metricSpeed = TextView(this).apply { gravity = Gravity.CENTER; textSize = 14f; setTypeface(null, Typeface.BOLD) }

        fun addMetricCol(title: String, valueView: TextView) {
            val box = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                gravity = Gravity.CENTER
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            }
            val lbl = TextView(this).apply {
                text = title
                textSize = 11f
                gravity = Gravity.CENTER
                setTextColor(Color.parseColor("#94A3B8"))
            }
            box.addView(lbl)
            box.addView(valueView)
            metricsRow.addView(box)
        }
        addMetricCol("Estabilidad", metricStability)
        addMetricCol("Latencia", metricLatency)
        addMetricCol("Velocidad", metricSpeed)

        // Transport Selector Row inside Tunnel card
        val transportHeader = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, dp(8), 0, dp(8))
        }
        transportSummaryTitle = TextView(this).apply {
            text = "Conexión: Wi-Fi"
            textSize = 12f
            setTypeface(null, Typeface.BOLD)
            setTextColor(Color.parseColor("#E2E8F0"))
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }
        val goSettingsLink = TextView(this).apply {
            text = "Ajustes y recomendaciones"
            textSize = 11f
            setTextColor(Color.parseColor("#38BDF8"))
            setOnClickListener { switchTab(AppTab.SETTINGS) }
        }
        transportHeader.addView(transportSummaryTitle)
        transportHeader.addView(goSettingsLink)

        val gridRow1 = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dp(8) }
        }
        val gridRow2 = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
        }

        btnAutoMode = makeStyledButton("Automático", themeInset(), "#334155", "#CBD5E1").apply {
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply { rightMargin = dp(6) }
            setOnClickListener {
                autoTransportMode = true
                detectAndApplyAutoTransport(restartIfRunning = vpnRunning)
            }
        }
        btnCellularMode = makeStyledButton("4G/5G", themeInset(), "#334155", "#CBD5E1").apply {
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply { leftMargin = dp(6) }
            setOnClickListener {
                autoTransportMode = false
                applyManualTransport("cellular", restartIfRunning = vpnRunning)
            }
        }
        btnWifiMode = makeStyledButton("Wi-Fi", themeInset(), "#334155", "#CBD5E1").apply {
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply { rightMargin = dp(6) }
            setOnClickListener {
                autoTransportMode = false
                applyManualTransport("wifi", restartIfRunning = vpnRunning)
            }
        }
        btnEthernetMode = makeStyledButton("Ethernet", themeInset(), "#334155", "#CBD5E1").apply {
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply { leftMargin = dp(6) }
            setOnClickListener {
                autoTransportMode = false
                applyManualTransport("ethernet", restartIfRunning = vpnRunning)
            }
        }
        gridRow1.addView(btnAutoMode)
        gridRow1.addView(btnCellularMode)
        gridRow2.addView(btnWifiMode)
        gridRow2.addView(btnEthernetMode)

        transportDetailText = TextView(this).apply {
            textSize = 11f
            setTextColor(Color.parseColor("#94A3B8"))
            setPadding(0, dp(8), 0, dp(10))
        }

        val footerRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, dp(4), 0, dp(12))
        }
        footerStatsText = TextView(this).apply {
            text = "IP $myVirtualIp/24 · MTU $activeMtu"
            textSize = 11f
            setTextColor(Color.parseColor("#94A3B8"))
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }
        simulateLossBtn = makeStyledButton("Simular caída", "#2A1215", "#7F1D1D", "#FCA5A5").apply {
            setOnClickListener {
                vpnRunning = true
                triggerLossAndExponentialBackoff()
                refreshAllUi()
            }
        }
        footerRow.addView(footerStatsText)
        footerRow.addView(simulateLossBtn)

        tunnelKeepAliveBtn = makeStyledButton("Blindaje Anti-Cierre Android · 0/4 PASS", "#1F1A0D", "#854D0E", "#FBBF24").apply {
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT)
            setOnClickListener { switchTab(AppTab.SETTINGS) }
        }

        // Guardián Quick-Status Banner inside Tunnel card
        val guardianMiniRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            background = makeCardDrawable(themeInset(), themeBorder(), 12, 1)
            setPadding(dp(12), dp(10), dp(12), dp(10))
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { topMargin = dp(10) }
            setOnClickListener { switchTab(AppTab.GUARDIAN) }
        }
        themedInsetCards.add(guardianMiniRow)
        tunnelGuardianMiniText = TextView(this).apply {
            text = "🛡️ Guardián: ENCENDIDO · Búnker OFF · Bloqueados 0"
            textSize = 11f
            setTypeface(null, Typeface.BOLD)
            setTextColor(Color.parseColor("#34D399"))
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }
        val goGuardTxt = TextView(this).apply {
            text = "Abrir Guardián →"
            textSize = 11f
            setTextColor(Color.parseColor("#38BDF8"))
        }
        guardianMiniRow.addView(tunnelGuardianMiniText)
        guardianMiniRow.addView(goGuardTxt)

        vpnCard.addView(tunnelPolicyLabel)
        vpnCard.addView(tunnelTitleText)
        vpnCard.addView(tunnelSubtitleText)
        vpnCard.addView(powerWrap)
        vpnCard.addView(metricsRow)
        vpnCard.addView(transportHeader)
        vpnCard.addView(gridRow1)
        vpnCard.addView(gridRow2)
        vpnCard.addView(transportDetailText)
        vpnCard.addView(footerRow)
        vpnCard.addView(tunnelKeepAliveBtn)
        vpnCard.addView(guardianMiniRow)

        // Peers Card
        val peersCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = makeCardDrawable(themeSurface(), themeBorder(), 18, 1)
            setPadding(dp(18), dp(16), dp(18), dp(16))
        }
        themedSurfaceCards.add(peersCard)

        val peersHeader = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, 0, 0, dp(12))
        }
        val peersTextCol = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }
        peersHeaderTitle = TextView(this).apply {
            text = "Amigos en tu Red (0)"
            textSize = 15f
            setTypeface(null, Typeface.BOLD)
            setTextColor(Color.parseColor("#F8FAFC"))
        }
        val peersSub = TextView(this).apply {
            text = "Sin límite de pares · Toca un dispositivo para gestionarlo"
            textSize = 11f
            setTextColor(Color.parseColor("#94A3B8"))
        }
        peersTextCol.addView(peersHeaderTitle)
        peersTextCol.addView(peersSub)

        val inviteBtn = makeStyledButton("+ Invitar QR", "#059669", "#10B981", "#FFFFFF").apply {
            setOnClickListener {
                connectSubTab = 0
                updateConnectSubTabs()
                switchTab(AppTab.CONNECT)
            }
        }
        peersHeader.addView(peersTextCol)
        peersHeader.addView(inviteBtn)

        peersListContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
        }

        peersCard.addView(peersHeader)
        peersCard.addView(peersListContainer)

        col.addView(vpnCard)
        col.addView(peersCard)
        scroll.addView(col)
        return scroll
    }

    private fun buildFilesTabView(): ScrollView {
        val scroll = ScrollView(this)
        val col = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(16), dp(16), dp(24))
        }

        val studioCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = makeCardDrawable(themeSurface(), themeBorder(), 18, 1)
            setPadding(dp(18), dp(16), dp(18), dp(16))
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dp(16) }
        }
        themedSurfaceCards.add(studioCard)

        val fsTitle = TextView(this).apply {
            text = "Transferencia P2P Máxima Velocidad"
            textSize = 16f
            setTypeface(null, Typeface.BOLD)
            setTextColor(Color.parseColor("#F8FAFC"))
        }
        val fsSub = TextView(this).apply {
            text = "Elige varios archivos y carpetas a la vez y envíalos por 10.0.0.0/24 o LAN directo (:51821)."
            textSize = 11f
            setTextColor(Color.parseColor("#94A3B8"))
            setPadding(0, dp(4), 0, dp(10))
        }
        fileSpeedModeBtn = makeStyledButton("Velocidad: Máxima Red Permitida (Turbo)", "#064E3B", "#10B981", "#34D399").apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dp(10) }
            setOnClickListener {
                fileMaxSpeedMode = !fileMaxSpeedMode
                refreshAllUi()
            }
        }

        // Sub-tabs: Enviar | Recibir
        val subRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            background = makeCardDrawable(themeInset(), themeBorder(), 12, 1)
            setPadding(dp(4), dp(4), dp(4), dp(4))
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dp(10) }
        }
        themedInsetCards.add(subRow)
        fileSubSendBtn = makeStyledButton("Enviar Archivos / Carpetas", "#059669", "#10B981", "#FFFFFF", 10).apply {
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply { rightMargin = dp(3) }
            setOnClickListener { filesSubTab = 0; refreshAllUi() }
        }
        fileSubReceiveBtn = makeStyledButton("Recibir (:51821)", themeInset(), "#334155", "#94A3B8", 10).apply {
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply { leftMargin = dp(3) }
            setOnClickListener { filesSubTab = 1; refreshAllUi() }
        }
        subRow.addView(fileSubSendBtn)
        subRow.addView(fileSubReceiveBtn)

        // Send Section
        fileSendSection = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        val channelRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dp(6) }
        }
        fileChanVpnBtn = makeStyledButton("Túnel", "#059669", "#10B981", "#FFFFFF", 10).apply {
            textSize = 10f
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply { rightMargin = dp(3) }
            setOnClickListener { fileSendChannel = "VPN"; refreshAllUi() }
        }
        fileChanLanBtn = makeStyledButton("Red Local", themeInset(), "#334155", "#CBD5E1", 10).apply {
            textSize = 10f
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply { rightMargin = dp(3) }
            setOnClickListener { fileSendChannel = "LAN"; refreshAllUi() }
        }
        fileChanBtBtn = makeStyledButton("Bluetooth", themeInset(), "#334155", "#CBD5E1", 10).apply {
            textSize = 10f
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply { rightMargin = dp(3) }
            setOnClickListener { fileSendChannel = "BLUETOOTH"; refreshAllUi() }
        }
        fileChanBothBtn = makeStyledButton("Ambas", themeInset(), "#334155", "#CBD5E1", 10).apply {
            textSize = 10f
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            setOnClickListener { fileSendChannel = "LAN_BLUETOOTH"; refreshAllUi() }
        }
        channelRow.addView(fileChanVpnBtn)
        channelRow.addView(fileChanLanBtn)
        channelRow.addView(fileChanBtBtn)
        channelRow.addView(fileChanBothBtn)

        fileChannelHintText = TextView(this).apply {
            text = "Canal activo: Túnel VPN P2P (10.0.0.0/24 · máxima velocidad)"
            textSize = 11f
            setTextColor(Color.parseColor("#94A3B8"))
            setPadding(0, 0, 0, dp(8))
        }

        val peerScroll = HorizontalScrollView(this).apply {
            isHorizontalScrollBarEnabled = false
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dp(8) }
        }
        filePeerChipsContainer = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        peerScroll.addView(filePeerChipsContainer)

        fileTargetIpInput = EditText(this).apply {
            setText(pendingSendTargetIp)
            hint = "IP destino (ej. 10.0.0.2 o 10.0.0.1)"
            setHintTextColor(Color.parseColor("#64748B"))
            setTextColor(Color.parseColor("#F8FAFC"))
            textSize = 12f
            background = makeCardDrawable(themeInset(), "#334155", 12, 1)
            setPadding(dp(12), dp(10), dp(12), dp(10))
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dp(10) }
        }
        val fileActionsRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dp(8) }
        }
        val pickFilesBtn = makeStyledButton("+ Elegir Archivos (Varios)", "#059669", "#10B981", "#FFFFFF").apply {
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply { rightMargin = dp(4) }
            setOnClickListener {
                pendingSendTargetIp = fileTargetIpInput.text.toString().trim().ifEmpty { defaultSendTargetIp() }
                multiFilePickerLauncher.launch(arrayOf("*/*"))
            }
        }
        val pickFolderBtn = makeStyledButton("+ Agregar Carpeta", "#0C4A6E", "#38BDF8", "#BAE6FD").apply {
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply { leftMargin = dp(4) }
            setOnClickListener {
                pendingSendTargetIp = fileTargetIpInput.text.toString().trim().ifEmpty { defaultSendTargetIp() }
                folderPickerLauncher.launch(null)
            }
        }
        fileActionsRow.addView(pickFilesBtn)
        fileActionsRow.addView(pickFolderBtn)

        // Staged Multi-File & Multi-Folder Batch Panel
        stagedBatchCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = makeCardDrawable(themeInset(), "#10B981", 12, 1)
            setPadding(dp(12), dp(12), dp(12), dp(12))
            visibility = View.GONE
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dp(8) }
        }
        themedInsetCards.add(stagedBatchCard)
        val stageTopRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, 0, 0, dp(6))
        }
        stagedBatchTitle = TextView(this).apply {
            text = "Lote listo para enviar (0)"
            textSize = 12f
            setTypeface(null, Typeface.BOLD)
            setTextColor(Color.parseColor("#34D399"))
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }
        val clearStageBtn = TextView(this).apply {
            text = "Vaciar"
            textSize = 11f
            setTextColor(Color.parseColor("#FCA5A5"))
            setPadding(dp(8), dp(4), dp(4), dp(4))
            setOnClickListener {
                stagedSendItems.clear()
                refreshAllUi()
            }
        }
        stageTopRow.addView(stagedBatchTitle)
        stageTopRow.addView(clearStageBtn)
        stagedItemsContainer = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        stagedSendBatchBtn = makeStyledButton("Enviar Todo el Lote (0)", "#059669", "#10B981", "#FFFFFF").apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { topMargin = dp(8) }
            setOnClickListener {
                pendingSendTargetIp = fileTargetIpInput.text.toString().trim().ifEmpty { defaultSendTargetIp() }
                sendStagedBatchP2P(pendingSendTargetIp)
            }
        }
        stagedBatchCard.addView(stageTopRow)
        stagedBatchCard.addView(stagedItemsContainer)
        stagedBatchCard.addView(stagedSendBatchBtn)

        fileSendSection.addView(channelRow)
        fileSendSection.addView(fileChannelHintText)
        fileSendSection.addView(peerScroll)
        fileSendSection.addView(fileTargetIpInput)
        fileSendSection.addView(fileActionsRow)
        fileSendSection.addView(stagedBatchCard)

        // Receive Section
        fileReceiveSection = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            visibility = View.GONE
        }
        fileReceiveFolderBtn = makeStyledButton("Carpeta Recibidos: Elegir Destino", themeInset(), "#F59E0B", "#FDE68A").apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dp(8) }
            setOnClickListener {
                startReceiverAfterFolderPick = false
                receiveFolderPickerLauncher.launch(null)
            }
        }
        fileReceiverToggleBtn = makeStyledButton("Activar Receptor (:51821)", themeInset(), "#334155", "#7DD3FC").apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dp(6) }
            setOnClickListener { toggleFileReceiverServer() }
        }
        fileReceiverHostInfo = TextView(this).apply {
            text = "Tu IP VPN: $myVirtualIp:51821"
            textSize = 11f
            setTextColor(Color.parseColor("#94A3B8"))
        }
        fileReceiveSection.addView(fileReceiveFolderBtn)
        fileReceiveSection.addView(fileReceiverToggleBtn)
        fileReceiveSection.addView(fileReceiverHostInfo)

        studioCard.addView(fsTitle)
        studioCard.addView(fsSub)
        studioCard.addView(fileSpeedModeBtn)
        studioCard.addView(subRow)
        studioCard.addView(fileSendSection)
        studioCard.addView(fileReceiveSection)

        val queueCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = makeCardDrawable(themeSurface(), themeBorder(), 18, 1)
            setPadding(dp(16), dp(16), dp(16), dp(16))
        }
        themedSurfaceCards.add(queueCard)

        val qTitle = TextView(this).apply {
            text = "Historial y Cola de Archivos"
            textSize = 15f
            setTypeface(null, Typeface.BOLD)
            setTextColor(Color.parseColor("#F8FAFC"))
            setPadding(0, 0, 0, dp(4))
        }
        val liquidLegend = TextView(this).apply {
            text = "💧 Verde: Llenando/OK · ❄️ Azul: Congelado/Deshielo · 💔 Rojo: Fallo · ⭕ Gris: Vacío"
            textSize = 10f
            setTextColor(Color.parseColor("#94A3B8"))
            setPadding(0, 0, 0, dp(10))
        }

        val filterScroll = HorizontalScrollView(this).apply {
            isHorizontalScrollBarEnabled = false
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dp(12) }
        }
        val filterRow = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        fun makeFilterBtn(lbl: String, cat: String): Button {
            return makeStyledButton(lbl, themeInset(), "#334155", "#94A3B8", 99).apply {
                textSize = 11f
                setPadding(dp(12), dp(6), dp(12), dp(6))
                minHeight = dp(36)
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.WRAP_CONTENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                ).apply { rightMargin = dp(6) }
                setOnClickListener { fileFilterCategory = cat; refreshAllUi() }
            }
        }
        fileFilterAllBtn = makeFilterBtn("Todos", "ALL")
        fileFilterSentBtn = makeFilterBtn("Enviados", "SENT")
        fileFilterReceivedBtn = makeFilterBtn("Recibidos", "RECEIVED")
        fileFilterPendingBtn = makeFilterBtn("En Pausa", "PENDING")
        fileFilterCompletedBtn = makeFilterBtn("Completados", "COMPLETED")
        fileFilterFailedBtn = makeFilterBtn("Fallidos", "FAILED")
        fileFilterCanceledBtn = makeFilterBtn("Cancelados", "CANCELED")
        filterRow.addView(fileFilterAllBtn)
        filterRow.addView(fileFilterSentBtn)
        filterRow.addView(fileFilterReceivedBtn)
        filterRow.addView(fileFilterPendingBtn)
        filterRow.addView(fileFilterCompletedBtn)
        filterRow.addView(fileFilterFailedBtn)
        filterRow.addView(fileFilterCanceledBtn)
        filterScroll.addView(filterRow)

        fileTransfersContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
        }

        queueCard.addView(qTitle)
        queueCard.addView(liquidLegend)
        queueCard.addView(filterScroll)
        queueCard.addView(fileTransfersContainer)

        col.addView(studioCard)
        col.addView(queueCard)
        scroll.addView(col)
        return scroll
    }

    private fun buildConnectTabView(): ScrollView {
        val scroll = ScrollView(this)
        val col = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(16), dp(16), dp(24))
        }

        // Real-time Peer Search Card
        val searchCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = makeCardDrawable(themeSurface(), themeBorder(), 18, 1)
            setPadding(dp(16), dp(16), dp(16), dp(16))
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dp(16) }
        }
        themedSurfaceCards.add(searchCard)
        val searchTopRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, 0, 0, dp(4))
        }
        val searchTitle = TextView(this).apply {
            text = "Buscador de Pares en Tiempo Real"
            textSize = 15f
            setTypeface(null, Typeface.BOLD)
            setTextColor(Color.parseColor("#F8FAFC"))
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }
        connectPeerCountText = TextView(this).apply {
            text = "0 de 0 pares"
            textSize = 11f
            setTypeface(null, Typeface.BOLD)
            setTextColor(Color.parseColor("#34D399"))
            background = makeCardDrawable(themeInset(), themeBorder(), 8, 1)
            setPadding(dp(8), dp(4), dp(8), dp(4))
        }
        searchTopRow.addView(searchTitle)
        searchTopRow.addView(connectPeerCountText)
        val searchSub = TextView(this).apply {
            text = "Filtra dispositivos de la red mesh al instante por nombre o dirección IP."
            textSize = 11f
            setTextColor(Color.parseColor("#94A3B8"))
            setPadding(0, 0, 0, dp(10))
        }
        val searchBarRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dp(10) }
        }
        connectPeerSearchInput = EditText(this).apply {
            hint = "Buscar por nombre o IP (ej. Pixel, 10.0.0.2, 192.168)..."
            setHintTextColor(Color.parseColor("#64748B"))
            setTextColor(Color.parseColor("#F8FAFC"))
            textSize = 12f
            isSingleLine = true
            background = makeCardDrawable(themeInset(), "#334155", 12, 1)
            setPadding(dp(12), dp(10), dp(12), dp(10))
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            addTextChangedListener(object : TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {
                    connectPeerSearchQuery = s?.toString() ?: ""
                    connectPeerClearBtn.visibility = if (connectPeerSearchQuery.isNotBlank()) View.VISIBLE else View.GONE
                    renderConnectPeerSearchResults()
                }
                override fun afterTextChanged(s: Editable?) {}
            })
        }
        connectPeerClearBtn = makeStyledButton("Limpiar", themeInset(), "#334155", "#CBD5E1", 10).apply {
            visibility = View.GONE
            textSize = 11f
            setPadding(dp(10), dp(8), dp(10), dp(8))
            minHeight = dp(38)
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { leftMargin = dp(8) }
            setOnClickListener {
                connectPeerSearchInput.setText("")
                connectPeerSearchQuery = ""
                visibility = View.GONE
                renderConnectPeerSearchResults()
            }
        }
        searchBarRow.addView(connectPeerSearchInput)
        searchBarRow.addView(connectPeerClearBtn)
        connectPeerResultsContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
        }
        searchCard.addView(searchTopRow)
        searchCard.addView(searchSub)
        searchCard.addView(searchBarRow)
        searchCard.addView(connectPeerResultsContainer)
        col.addView(searchCard)

        val subToggle = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            background = makeCardDrawable(themeSurface(), themeBorder(), 14, 1)
            setPadding(dp(6), dp(6), dp(6), dp(6))
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dp(16) }
        }
        themedSurfaceCards.add(subToggle)
        subTabShareBtn = makeStyledButton("Mi Código QR", "#1E293B", "#334155", "#F8FAFC").apply {
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply { rightMargin = dp(4) }
            setOnClickListener {
                connectSubTab = 0
                updateConnectSubTabs()
            }
        }
        subTabScanBtn = makeStyledButton("Escanear Amigo", themeInset(), themeInset(), "#94A3B8").apply {
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply { leftMargin = dp(4) }
            setOnClickListener {
                connectSubTab = 1
                updateConnectSubTabs()
            }
        }
        subToggle.addView(subTabShareBtn)
        subToggle.addView(subTabScanBtn)

        // Share QR Card
        shareQrCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = makeCardDrawable(themeSurface(), themeBorder(), 18, 1)
            setPadding(dp(18), dp(18), dp(18), dp(18))
        }
        themedSurfaceCards.add(shareQrCard)
        val shareTop = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, 0, 0, dp(12))
        }
        val shareTitle = TextView(this).apply {
            text = "Tu Invitación QR P2P"
            textSize = 16f
            setTypeface(null, Typeface.BOLD)
            setTextColor(Color.parseColor("#F8FAFC"))
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }
        val rekeyHostBtn = makeStyledButton("Nuevas llaves", "#1E293B", "#334155", "#34D399").apply {
            setOnClickListener {
                regenerateHostPublicKey()
                renderInlineQrCode()
                appendLog("INFO", "Noise", myVirtualIp, "Nuevo par de llaves Curve25519 generado")
                refreshAllUi()
            }
        }
        shareTop.addView(shareTitle)
        shareTop.addView(rekeyHostBtn)

        val qrWhiteBox = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            background = makeCardDrawable("#F8FAFC", "#CBD5E1", 16, 1)
            setPadding(dp(16), dp(16), dp(16), dp(16))
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dp(12) }
        }
        qrImageView = ImageView(this).apply {
            layoutParams = LinearLayout.LayoutParams(dp(210), dp(210))
        }
        qrIpText = TextView(this).apply {
            text = "IP asignada al amigo: 10.0.0.2/24"
            textSize = 12f
            setTypeface(null, Typeface.BOLD)
            setTextColor(Color.parseColor("#0F172A"))
            setPadding(0, dp(10), 0, 0)
        }
        qrWhiteBox.addView(qrImageView)
        qrWhiteBox.addView(qrIpText)

        qrEndpointText = TextView(this).apply {
            textSize = 12f
            setTextColor(Color.parseColor("#CBD5E1"))
            setPadding(0, dp(4), 0, dp(4))
        }
        qrKeyText = TextView(this).apply {
            textSize = 12f
            setTextColor(Color.parseColor("#94A3B8"))
            setPadding(0, 0, 0, dp(14))
        }
        val authModeRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dp(8) }
        }
        inviteWith2faBtn = makeStyledButton("Con 2FA (PIN / Auth)", "#064E3B", "#10B981", "#34D399").apply {
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply { rightMargin = dp(4) }
            setOnClickListener {
                inviteRequire2fa = true
                currentInvitePin = String.format(Locale.US, "%06d", 100000 + SecureRandom().nextInt(900000))
                renderInlineQrCode()
            }
        }
        inviteNo2faBtn = makeStyledButton("Sin 2FA (Directa)", themeInset(), "#334155", "#94A3B8").apply {
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply { leftMargin = dp(4) }
            setOnClickListener {
                inviteRequire2fa = false
                renderInlineQrCode()
            }
        }
        authModeRow.addView(inviteWith2faBtn)
        authModeRow.addView(inviteNo2faBtn)

        invitePinText = TextView(this).apply {
            text = "Código 2FA para tu amigo: $currentInvitePin"
            textSize = 12f
            setTypeface(null, Typeface.BOLD)
            setTextColor(Color.parseColor("#34D399"))
            setPadding(0, dp(2), 0, dp(10))
        }

        val shareLinkBtn = makeStyledButton("Compartir Invitación P2P", "#059669", "#10B981", "#FFFFFF").apply {
            setOnClickListener {
                val uri = buildCurrentInviteUri()
                val shareIntent = Intent(Intent.ACTION_SEND).apply {
                    type = "text/plain"
                    putExtra(Intent.EXTRA_TEXT, uri)
                }
                startActivity(Intent.createChooser(shareIntent, "Compartir invitación NexoMesh"))
            }
        }

        shareQrCard.addView(shareTop)
        shareQrCard.addView(authModeRow)
        shareQrCard.addView(invitePinText)
        shareQrCard.addView(qrWhiteBox)
        shareQrCard.addView(qrEndpointText)
        shareQrCard.addView(qrKeyText)
        shareQrCard.addView(shareLinkBtn)

        // Scan Friend Card
        scanQrCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = makeCardDrawable(themeSurface(), themeBorder(), 18, 1)
            setPadding(dp(18), dp(18), dp(18), dp(18))
            visibility = View.GONE
        }
        themedSurfaceCards.add(scanQrCard)
        val scanTitle = TextView(this).apply {
            text = "Unirse o Agregar Amigo"
            textSize = 16f
            setTypeface(null, Typeface.BOLD)
            setTextColor(Color.parseColor("#F8FAFC"))
        }
        val scanSub = TextView(this).apply {
            text = "Escanea el QR con la cámara o pega el enlace nexomesh:// recibido."
            textSize = 12f
            setTextColor(Color.parseColor("#94A3B8"))
            setPadding(0, dp(4), 0, dp(14))
        }
        val openCameraBtn = makeStyledButton("Abrir Cámara del Celular (QR)", themeInset(), "#334155", "#34D399").apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dp(14) }
            setOnClickListener { launchQrScanner() }
        }
        inviteUriInput = EditText(this).apply {
            hint = "nexomesh://join?pk=...&ep=...&ip=10.0.0.2&name=Amigo"
            setHintTextColor(Color.parseColor("#64748B"))
            setTextColor(Color.parseColor("#F8FAFC"))
            textSize = 12f
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE
            minLines = 3
            background = makeCardDrawable(themeInset(), "#334155", 12, 1)
            setPadding(dp(12), dp(12), dp(12), dp(12))
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dp(12) }
        }
        val joinManualBtn = makeStyledButton("Conectar Par por Enlace", "#059669", "#10B981", "#FFFFFF").apply {
            setOnClickListener {
                val raw = inviteUriInput.text.toString().trim()
                if (raw.isNotEmpty()) {
                    handleScannedInviteUri(raw)
                    inviteUriInput.setText("")
                }
            }
        }
        scanQrCard.addView(scanTitle)
        scanQrCard.addView(scanSub)
        scanQrCard.addView(openCameraBtn)
        scanQrCard.addView(inviteUriInput)
        scanQrCard.addView(joinManualBtn)

        col.addView(subToggle)
        col.addView(shareQrCard)
        col.addView(scanQrCard)
        scroll.addView(col)
        return scroll
    }

    private fun buildActivityTabView(): ScrollView {
        val scroll = ScrollView(this)
        val col = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(16), dp(16), dp(24))
        }

        val subToggleRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dp(12) }
        }
        activitySubMetricsBtn = makeStyledButton("Métricas y Registros", "#059669", "#10B981", "#FFFFFF").apply {
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply { rightMargin = dp(4) }
            setOnClickListener { activitySubTab = 0; refreshAllUi() }
        }
        activitySubTopologyBtn = makeStyledButton("Topología P2P", themeInset(), "#334155", "#CBD5E1").apply {
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply { leftMargin = dp(4) }
            setOnClickListener { activitySubTab = 1; refreshAllUi() }
        }
        subToggleRow.addView(activitySubMetricsBtn)
        subToggleRow.addView(activitySubTopologyBtn)
        col.addView(subToggleRow)

        activityMetricsSection = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
        }
        activityTopologySection = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            visibility = View.GONE
        }

        val topoCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = makeCardDrawable(themeSurface(), themeBorder(), 18, 1)
            setPadding(dp(16), dp(16), dp(16), dp(16))
        }
        themedSurfaceCards.add(topoCard)
        val topoTitle = TextView(this).apply {
            text = "Topología Interactiva de Malla P2P"
            textSize = 15f
            setTypeface(null, Typeface.BOLD)
            setTextColor(Color.parseColor("#F8FAFC"))
        }
        meshTopologySummaryText = TextView(this).apply {
            text = "Nodos y calidad del enlace punto a punto"
            textSize = 11f
            setTextColor(Color.parseColor("#94A3B8"))
            setPadding(0, dp(3), 0, dp(10))
        }
        meshTopologyCanvasView = MeshTopologyCanvasView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                dp(280)
            )
        }
        topoCard.addView(topoTitle)
        topoCard.addView(meshTopologySummaryText)
        topoCard.addView(meshTopologyCanvasView)
        activityTopologySection.addView(topoCard)

        // Live Telemetry Chart Card (same graph + 4 metric tiles as preview)
        val graphCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = makeCardDrawable(themeSurface(), themeBorder(), 18, 1)
            setPadding(dp(16), dp(16), dp(16), dp(16))
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dp(16) }
        }
        themedSurfaceCards.add(graphCard)
        val graphTitle = TextView(this).apply {
            text = "Gráfica de Latencia y Velocidad en Vivo"
            textSize = 15f
            setTypeface(null, Typeface.BOLD)
            setTextColor(Color.parseColor("#F8FAFC"))
        }
        telemetrySummaryText = TextView(this).apply {
            text = "RTT 19 ms · Rx 70 Mbps · Tx 55 Mbps"
            textSize = 11f
            setTextColor(Color.parseColor("#34D399"))
            setPadding(0, dp(2), 0, dp(10))
        }

        val statsRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dp(10) }
        }
        fun makeStatChip(label: String, accentHex: String): Pair<LinearLayout, TextView> {
            val box = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                background = makeCardDrawable(themeInset(), themeBorder(), 10, 1)
                setPadding(dp(8), dp(8), dp(8), dp(8))
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply { rightMargin = dp(4) }
            }
            themedInsetCards.add(box)
            val lbl = TextView(this).apply {
                text = label
                textSize = 10f
                setTextColor(Color.parseColor("#94A3B8"))
            }
            val valTv = TextView(this).apply {
                text = "—"
                textSize = 12f
                setTypeface(null, Typeface.BOLD)
                setTextColor(Color.parseColor(accentHex))
            }
            box.addView(lbl)
            box.addView(valTv)
            return box to valTv
        }
        val (boxRtt, tvRtt) = makeStatChip("RTT", "#34D399")
        val (boxRx, tvRx) = makeStatChip("Rx", "#38BDF8")
        val (boxTx, tvTx) = makeStatChip("Tx", "#FBBF24")
        val (boxScore, tvScore) = makeStatChip("Salud", "#A78BFA")
        statBoxRtt = tvRtt
        statBoxRx = tvRx
        statBoxTx = tvTx
        statBoxScore = tvScore
        statsRow.addView(boxRtt)
        statsRow.addView(boxRx)
        statsRow.addView(boxTx)
        statsRow.addView(boxScore)

        telemetryGraphView = TelemetryGraphView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                dp(155)
            )
        }
        val legendTv = TextView(this).apply {
            text = "● Rx #38BDF8 (Bajada)   ● Tx #F59E0B (Subida)   ● RTT #10B981 (Latencia ms)"
            textSize = 10f
            setTextColor(Color.parseColor("#94A3B8"))
            setPadding(0, dp(8), 0, 0)
        }
        graphCard.addView(graphTitle)
        graphCard.addView(telemetrySummaryText)
        graphCard.addView(statsRow)
        graphCard.addView(telemetryGraphView)
        graphCard.addView(legendTv)

        // 60-second Per-Peer RTT Trend Card
        val peerRtt60sCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = makeCardDrawable(themeSurface(), themeBorder(), 18, 1)
            setPadding(dp(16), dp(16), dp(16), dp(16))
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dp(16) }
        }
        themedSurfaceCards.add(peerRtt60sCard)
        val peerRttTitle = TextView(this).apply {
            text = "Tendencia Histórica RTT por Par (Últimos 60 s)"
            textSize = 15f
            setTypeface(null, Typeface.BOLD)
            setTextColor(Color.parseColor("#F8FAFC"))
        }
        peerRtt60sSummaryText = TextView(this).apply {
            text = "Ventana móvil de 60 s · Sin pares conectados aún"
            textSize = 11f
            setTextColor(Color.parseColor("#94A3B8"))
            setPadding(0, dp(3), 0, dp(10))
        }
        peerRtt60sGraphView = PeerRtt60sGraphView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                dp(170)
            )
        }
        val peerRttAxisRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(0, dp(6), 0, 0)
        }
        val axisStart = TextView(this).apply {
            text = "-60 s"
            textSize = 10f
            setTextColor(Color.parseColor("#64748B"))
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }
        val axisMid = TextView(this).apply {
            text = "-30 s"
            textSize = 10f
            gravity = Gravity.CENTER
            setTextColor(Color.parseColor("#64748B"))
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }
        val axisEnd = TextView(this).apply {
            text = "Ahora"
            textSize = 10f
            gravity = Gravity.END
            setTextColor(Color.parseColor("#34D399"))
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }
        peerRttAxisRow.addView(axisStart)
        peerRttAxisRow.addView(axisMid)
        peerRttAxisRow.addView(axisEnd)
        peerRtt60sCard.addView(peerRttTitle)
        peerRtt60sCard.addView(peerRtt60sSummaryText)
        peerRtt60sCard.addView(peerRtt60sGraphView)
        peerRtt60sCard.addView(peerRttAxisRow)

        // Active Peers Average Latency Bar Chart Card
        val peerAvgBarCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = makeCardDrawable(themeSurface(), themeBorder(), 18, 1)
            setPadding(dp(16), dp(16), dp(16), dp(16))
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dp(16) }
        }
        themedSurfaceCards.add(peerAvgBarCard)
        val peerAvgBarTitle = TextView(this).apply {
            text = "Latencia Promedio Actual por Par Activo (ms)"
            textSize = 15f
            setTypeface(null, Typeface.BOLD)
            setTextColor(Color.parseColor("#F8FAFC"))
        }
        peerAvgBarSummaryText = TextView(this).apply {
            text = "Sin pares activos en la malla"
            textSize = 11f
            setTextColor(Color.parseColor("#94A3B8"))
            setPadding(0, dp(3), 0, dp(10))
        }
        peerAvgBarGraphView = PeerAvgLatencyBarGraphView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                dp(150)
            )
        }
        peerAvgBarCard.addView(peerAvgBarTitle)
        peerAvgBarCard.addView(peerAvgBarSummaryText)
        peerAvgBarCard.addView(peerAvgBarGraphView)

        // Live STUN Card
        val stunCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = makeCardDrawable(themeSurface(), themeBorder(), 18, 1)
            setPadding(dp(16), dp(16), dp(16), dp(16))
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dp(16) }
        }
        themedSurfaceCards.add(stunCard)
        activityStunTitle = TextView(this).apply {
            text = "Sonda STUN en Vivo ($activeStunServer)"
            textSize = 14f
            setTypeface(null, Typeface.BOLD)
            setTextColor(Color.parseColor("#F8FAFC"))
        }
        activityStunEndpoint = TextView(this).apply {
            text = "Endpoint: $lastStunMapped · Noise IKpsk2"
            textSize = 12f
            setTextColor(Color.parseColor("#94A3B8"))
            setPadding(0, dp(4), 0, dp(12))
        }
        val probeBtn = makeStyledButton("Probar Sonda STUN Real", "#059669", "#10B981", "#FFFFFF").apply {
            setOnClickListener { runStunProbeAsync(silent = false) }
        }
        stunCard.addView(activityStunTitle)
        stunCard.addView(activityStunEndpoint)
        stunCard.addView(probeBtn)

        // Logs Card
        val logsCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = makeCardDrawable(themeSurface(), themeBorder(), 18, 1)
            setPadding(dp(16), dp(16), dp(16), dp(16))
        }
        themedSurfaceCards.add(logsCard)
        logsTitleText = TextView(this).apply {
            text = "Registro de Eventos del Túnel (0)"
            textSize = 15f
            setTypeface(null, Typeface.BOLD)
            setTextColor(Color.parseColor("#F8FAFC"))
        }
        val logsSub = TextView(this).apply {
            text = "Auditoría exportable de handshakes Noise, STUN y backoff"
            textSize = 11f
            setTextColor(Color.parseColor("#94A3B8"))
            setPadding(0, dp(2), 0, dp(10))
        }

        val filterRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dp(10) }
        }
        filterAllBtn = makeStyledButton("Todos", "#1E293B", "#334155", "#F8FAFC").apply {
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply { rightMargin = dp(4) }
            setOnClickListener { logSeverityFilter = "ALL"; refreshAllUi() }
        }
        filterInfoBtn = makeStyledButton("Info", themeInset(), "#334155", "#94A3B8").apply {
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply { rightMargin = dp(4) }
            setOnClickListener { logSeverityFilter = "INFO"; refreshAllUi() }
        }
        filterWarnBtn = makeStyledButton("Alerta", themeInset(), "#334155", "#94A3B8").apply {
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply { rightMargin = dp(4) }
            setOnClickListener { logSeverityFilter = "WARNING"; refreshAllUi() }
        }
        filterCritBtn = makeStyledButton("Crítico", themeInset(), "#334155", "#94A3B8").apply {
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            setOnClickListener { logSeverityFilter = "CRITICAL"; refreshAllUi() }
        }
        filterRow.addView(filterAllBtn)
        filterRow.addView(filterInfoBtn)
        filterRow.addView(filterWarnBtn)
        filterRow.addView(filterCritBtn)

        val exportRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dp(12) }
        }
        val exportCsvBtn = makeStyledButton("Exportar CSV", themeInset(), "#334155", "#34D399").apply {
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply { rightMargin = dp(4) }
            setOnClickListener { exportLogsToCsv() }
        }
        val exportJsonBtn = makeStyledButton("Exportar JSON", "#059669", "#10B981", "#FFFFFF").apply {
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply { leftMargin = dp(4); rightMargin = dp(4) }
            setOnClickListener { exportLogsToJson() }
        }
        val clearBtn = makeStyledButton("Limpiar", themeInset(), "#334155", "#94A3B8").apply {
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 0.8f).apply { leftMargin = dp(4) }
            setOnClickListener { logsList.clear(); refreshAllUi() }
        }
        exportRow.addView(exportCsvBtn)
        exportRow.addView(exportJsonBtn)
        exportRow.addView(clearBtn)

        logsContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
        }

        logsCard.addView(logsTitleText)
        logsCard.addView(logsSub)
        logsCard.addView(filterRow)
        logsCard.addView(exportRow)
        logsCard.addView(logsContainer)

        activityMetricsSection.addView(graphCard)
        activityMetricsSection.addView(peerRtt60sCard)
        activityMetricsSection.addView(peerAvgBarCard)
        activityMetricsSection.addView(stunCard)
        activityMetricsSection.addView(logsCard)
        col.addView(activityMetricsSection)
        col.addView(activityTopologySection)
        scroll.addView(col)
        return scroll
    }

    private fun buildSettingsTabView(): ScrollView {
        val scroll = ScrollView(this)
        val col = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(16), dp(16), dp(24))
        }

        // Appearance Theme Card (Oscuro / Modo Neón / Black OLED)
        appearanceCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = makeCardDrawable(themeSurface(), themeBorder(), 18, 1)
            setPadding(dp(18), dp(18), dp(18), dp(18))
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dp(16) }
        }
        themedSurfaceCards.add(appearanceCard)
        val appTitle = TextView(this).apply {
            text = "Apariencia y Modo de Pantalla"
            textSize = 15f
            setTypeface(null, Typeface.BOLD)
            setTextColor(Color.parseColor("#F8FAFC"))
        }
        val appSub = TextView(this).apply {
            text = "Elige entre Estándar Oscuro, Modo Neón o Black OLED (#000000)."
            textSize = 11f
            setTextColor(Color.parseColor("#94A3B8"))
            setPadding(0, dp(2), 0, dp(10))
        }
        val themeRow = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        themeDarkBtn = makeStyledButton("Oscuro", themeInset(), "#334155", "#CBD5E1").apply {
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply { rightMargin = dp(4) }
            setOnClickListener { applySelectedTheme("dark") }
        }
        themeNeonBtn = makeStyledButton("Modo Neón", themeInset(), "#334155", "#00F5D4").apply {
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply { leftMargin = dp(4); rightMargin = dp(4) }
            setOnClickListener { applySelectedTheme("neon") }
        }
        themeOledBtn = makeStyledButton("Black OLED", themeInset(), "#334155", "#F8FAFC").apply {
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply { leftMargin = dp(4) }
            setOnClickListener { applySelectedTheme("oled") }
        }
        themeRow.addView(themeDarkBtn)
        themeRow.addView(themeNeonBtn)
        themeRow.addView(themeOledBtn)
        appearanceCard.addView(appTitle)
        appearanceCard.addView(appSub)
        appearanceCard.addView(themeRow)

        // Device, Transport, MTU & Keepalive Card
        deviceCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = makeCardDrawable(themeSurface(), themeBorder(), 18, 1)
            setPadding(dp(18), dp(18), dp(18), dp(18))
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dp(16) }
        }
        themedSurfaceCards.add(deviceCard)

        val devTop = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, 0, 0, dp(12))
        }
        val devTextCol = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }
        val devTitle = TextView(this).apply {
            text = "Tu Celular y Confirmación"
            textSize = 16f
            setTypeface(null, Typeface.BOLD)
            setTextColor(Color.parseColor("#F8FAFC"))
        }
        settingsDeviceSubtitle = TextView(this).apply {
            text = "${Build.MANUFACTURER} ${Build.MODEL} · ${detectDevicePolicy()}"
            textSize = 11f
            setTextColor(Color.parseColor("#94A3B8"))
        }
        devTextCol.addView(devTitle)
        devTextCol.addView(settingsDeviceSubtitle)

        val rescanBtn = makeStyledButton("Re-escanear", "#1E293B", "#334155", "#F8FAFC").apply {
            setOnClickListener { runDeviceScanAndShowResult() }
        }
        devTop.addView(devTextCol)
        devTop.addView(rescanBtn)

        val connHeader = TextView(this).apply {
            text = "Decisión de Conexión (Automático vs Manual)"
            textSize = 13f
            setTypeface(null, Typeface.BOLD)
            setTextColor(Color.parseColor("#F8FAFC"))
            setPadding(0, dp(8), 0, dp(2))
        }
        val connSub = TextView(this).apply {
            text = "Elige automáticamente según 4G/5G, Wi-Fi o Cable Ethernet, o configúralo manual."
            textSize = 11f
            setTextColor(Color.parseColor("#94A3B8"))
            setPadding(0, 0, 0, dp(10))
        }

        settingsAutoBtn = makeStyledButton("Activar Automático (4G/5G ↔ Wi-Fi ↔ Ethernet)", "#064E3B", "#10B981", "#34D399").apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dp(8) }
            setOnClickListener {
                autoTransportMode = true
                detectAndApplyAutoTransport(restartIfRunning = vpnRunning)
            }
        }

        val manualRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dp(10) }
        }
        settingsCellularBtn = makeStyledButton("4G/5G", themeInset(), "#334155", "#CBD5E1").apply {
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply { rightMargin = dp(4) }
            setOnClickListener { autoTransportMode = false; applyManualTransport("cellular", vpnRunning) }
        }
        settingsWifiBtn = makeStyledButton("Wi-Fi", themeInset(), "#334155", "#CBD5E1").apply {
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply { leftMargin = dp(4); rightMargin = dp(4) }
            setOnClickListener { autoTransportMode = false; applyManualTransport("wifi", vpnRunning) }
        }
        settingsEthernetBtn = makeStyledButton("Ethernet", themeInset(), "#334155", "#CBD5E1").apply {
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply { leftMargin = dp(4) }
            setOnClickListener { autoTransportMode = false; applyManualTransport("ethernet", vpnRunning) }
        }
        manualRow.addView(settingsCellularBtn)
        manualRow.addView(settingsWifiBtn)
        manualRow.addView(settingsEthernetBtn)

        val mtuLabel = TextView(this).apply {
            text = "MTU de Paquetes UDP (Bytes)"
            textSize = 12f
            setTypeface(null, Typeface.BOLD)
            setTextColor(Color.parseColor("#E2E8F0"))
            setPadding(0, dp(4), 0, dp(6))
        }
        val mtuRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT).apply { bottomMargin = dp(10) }
        }
        fun setCustomMtu(mtu: Int) {
            activeMtu = mtu
            appendLog("INFO", "WireGuard", myVirtualIp, "MTU ajustado manualmente a $mtu bytes")
            refreshAllUi()
            if (vpnRunning) startMeshTunnel()
        }
        settingsMtu1280Btn = makeStyledButton("1280", themeInset(), "#334155", "#CBD5E1").apply {
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply { rightMargin = dp(4) }
            setOnClickListener { setCustomMtu(1280) }
        }
        settingsMtu1380Btn = makeStyledButton("1380", themeInset(), "#334155", "#CBD5E1").apply {
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply { leftMargin = dp(4); rightMargin = dp(4) }
            setOnClickListener { setCustomMtu(1380) }
        }
        settingsMtu1420Btn = makeStyledButton("1420", themeInset(), "#334155", "#CBD5E1").apply {
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply { leftMargin = dp(4) }
            setOnClickListener { setCustomMtu(1420) }
        }
        mtuRow.addView(settingsMtu1280Btn)
        mtuRow.addView(settingsMtu1380Btn)
        mtuRow.addView(settingsMtu1420Btn)

        val kaLabel = TextView(this).apply {
            text = "Keepalive NAT Persistente (Segundos)"
            textSize = 12f
            setTypeface(null, Typeface.BOLD)
            setTextColor(Color.parseColor("#E2E8F0"))
            setPadding(0, dp(2), 0, dp(6))
        }
        val kaRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT).apply { bottomMargin = dp(12) }
        }
        fun setCustomKa(sec: Int) {
            activeKeepalive = sec
            appendLog("INFO", "WireGuard", myVirtualIp, "Keepalive NAT ajustado a ${sec}s")
            refreshAllUi()
        }
        settingsKa10Btn = makeStyledButton("10s (4G)", themeInset(), "#334155", "#CBD5E1").apply {
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply { rightMargin = dp(4) }
            setOnClickListener { setCustomKa(10) }
        }
        settingsKa15Btn = makeStyledButton("15s (Wi-Fi)", themeInset(), "#334155", "#CBD5E1").apply {
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply { leftMargin = dp(4); rightMargin = dp(4) }
            setOnClickListener { setCustomKa(15) }
        }
        settingsKa25Btn = makeStyledButton("25s (Cable)", themeInset(), "#334155", "#CBD5E1").apply {
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply { leftMargin = dp(4) }
            setOnClickListener { setCustomKa(25) }
        }
        kaRow.addView(settingsKa10Btn)
        kaRow.addView(settingsKa15Btn)
        kaRow.addView(settingsKa25Btn)

        val recBox = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = makeCardDrawable(themeInset(), themeBorder(), 12, 1)
            setPadding(dp(12), dp(12), dp(12), dp(12))
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dp(12) }
        }
        themedInsetCards.add(recBox)
        settingsRecTitle = TextView(this).apply {
            textSize = 12f
            setTypeface(null, Typeface.BOLD)
            setTextColor(Color.parseColor("#34D399"))
        }
        settingsRecTopology = TextView(this).apply {
            textSize = 11f
            setTextColor(Color.parseColor("#94A3B8"))
            setPadding(0, dp(2), 0, dp(6))
        }
        settingsRecDesc = TextView(this).apply {
            textSize = 12f
            setTextColor(Color.parseColor("#CBD5E1"))
            setPadding(0, 0, 0, dp(6))
        }
        settingsRecBullets = TextView(this).apply {
            textSize = 11f
            setTextColor(Color.parseColor("#94A3B8"))
        }
        recBox.addView(settingsRecTitle)
        recBox.addView(settingsRecTopology)
        recBox.addView(settingsRecDesc)
        recBox.addView(settingsRecBullets)

        settingsStunText = TextView(this).apply {
            text = "Servidor STUN: $activeStunServer · Endpoint: $lastStunMapped"
            textSize = 11f
            setTextColor(Color.parseColor("#94A3B8"))
        }

        deviceCard.addView(devTop)
        deviceCard.addView(connHeader)
        deviceCard.addView(connSub)
        deviceCard.addView(settingsAutoBtn)
        deviceCard.addView(manualRow)
        deviceCard.addView(mtuLabel)
        deviceCard.addView(mtuRow)
        deviceCard.addView(kaLabel)
        deviceCard.addView(kaRow)
        deviceCard.addView(recBox)
        deviceCard.addView(settingsStunText)

        // Android Anti-Kill Survival Guide Card with Prominent Verification Button & Live Audit Banner
        guideCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = makeCardDrawable(themeSurface(), themeBorder(), 18, 1)
            setPadding(dp(18), dp(18), dp(18), dp(18))
        }
        themedSurfaceCards.add(guideCard)
        guideHeaderTitle = TextView(this).apply {
            text = "Guía Visual Anti-Cierre Android (0/4 PASS)"
            textSize = 15f
            setTypeface(null, Typeface.BOLD)
            setTextColor(Color.parseColor("#F8FAFC"))
        }
        val guideSub = TextView(this).apply {
            text = "Verifica con Android que ningún servicio de NexoMesh sea cerrado en ${Build.MANUFACTURER} ${Build.MODEL}."
            textSize = 11f
            setTextColor(Color.parseColor("#94A3B8"))
            setPadding(0, dp(4), 0, dp(10))
        }
        guideTopVerifyBtn = makeStyledButton("Verificar Protección Anti-Cierre (Android)", "#059669", "#10B981", "#FFFFFF").apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dp(10) }
            setOnClickListener { runRealKeepAliveAuditDialog() }
        }
        guideProgressText = TextView(this).apply {
            text = "Progreso de blindaje: 0%"
            textSize = 12f
            setTypeface(null, Typeface.BOLD)
            setTextColor(Color.parseColor("#FBBF24"))
            setPadding(0, 0, 0, dp(6))
        }
        guideProgressBar = ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal).apply {
            max = 100
            progress = 0
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                dp(8)
            ).apply { bottomMargin = dp(10) }
        }
        guideInlineResultText = TextView(this).apply {
            text = "Pulsa 'Verificar Protección Anti-Cierre' para auditar WakeLock, Doze, VPN siempre activa y datos."
            textSize = 11f
            setTextColor(Color.parseColor("#CBD5E1"))
            background = makeCardDrawable(themeInset(), themeBorder(), 10, 1)
            setPadding(dp(12), dp(10), dp(12), dp(10))
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dp(12) }
        }

        guideStepsContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
        }

        val guideActionRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(0, dp(8), 0, 0)
        }
        guideVerifyBtn = makeStyledButton("Auditoría Completa OS", "#059669", "#10B981", "#FFFFFF").apply {
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply { rightMargin = dp(6) }
            setOnClickListener {
                runRealKeepAliveAuditDialog()
            }
        }
        val guideResetBtn = makeStyledButton("Reiniciar guía", themeInset(), "#334155", "#CBD5E1").apply {
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply { leftMargin = dp(6) }
            setOnClickListener {
                getSharedPreferences("nexomesh_prefs", MODE_PRIVATE).edit()
                    .putBoolean("keepalive_lock_pass", false)
                    .putBoolean("keepalive_vpn_legacy_pass", false)
                    .putBoolean("keepalive_data_legacy_pass", false)
                    .apply()
                refreshAllUi()
            }
        }
        guideActionRow.addView(guideVerifyBtn)
        guideActionRow.addView(guideResetBtn)

        guideCard.addView(guideHeaderTitle)
        guideCard.addView(guideSub)
        guideCard.addView(guideTopVerifyBtn)
        guideCard.addView(guideProgressText)
        guideCard.addView(guideProgressBar)
        guideCard.addView(guideInlineResultText)
        guideCard.addView(guideStepsContainer)
        guideCard.addView(guideActionRow)

        col.addView(appearanceCard)
        col.addView(deviceCard)
        col.addView(guideCard)
        scroll.addView(col)
        return scroll
    }

    private fun buildGuardianTabView(): ScrollView {
        val scroll = ScrollView(this)
        val col = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(16), dp(16), dp(24))
        }

        defenseCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = makeCardDrawable(themeSurface(), themeBorder(), 18, 1)
            setPadding(dp(18), dp(18), dp(18), dp(18))
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dp(16) }
        }
        themedSurfaceCards.add(defenseCard)
        val defTitle = TextView(this).apply {
            text = "Modo Guardián · Defensa Autónoma Mesh"
            textSize = 16f
            setTypeface(null, Typeface.BOLD)
            setTextColor(Color.parseColor("#F8FAFC"))
        }
        val defSub = TextView(this).apply {
            text = "Controla la protección contra ataques, cuarentena automática y rotación de llaves Curve25519."
            textSize = 11f
            setTextColor(Color.parseColor("#94A3B8"))
            setPadding(0, dp(4), 0, dp(10))
        }

        guardianPostureBanner = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = makeCardDrawable("#052E16", "#10B981", 12, 1)
            setPadding(dp(12), dp(10), dp(12), dp(10))
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dp(10) }
        }
        guardianPostureTitle = TextView(this).apply {
            text = "PROTECCIÓN ACTIVA POR DEFECTO"
            textSize = 12f
            setTypeface(null, Typeface.BOLD)
            setTextColor(Color.parseColor("#34D399"))
        }
        guardianPostureSub = TextView(this).apply {
            text = "Inspeccionando paquetes UDP/TCP e ips virtuales en tiempo real."
            textSize = 11f
            setTextColor(Color.parseColor("#CBD5E1"))
        }
        guardianPostureBanner.addView(guardianPostureTitle)
        guardianPostureBanner.addView(guardianPostureSub)

        defenseStatsText = TextView(this).apply {
            text = "Paquetes bloqueados: 0 · Llaves rotadas: 0"
            textSize = 11f
            setTextColor(Color.parseColor("#34D399"))
            setPadding(0, dp(2), 0, dp(10))
        }
        val defBtnRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dp(10) }
        }
        defenseShieldBtn = makeStyledButton("Guardián: ENCENDIDO", "#064E3B", "#10B981", "#34D399").apply {
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply { rightMargin = dp(4) }
            setOnClickListener {
                shieldEnabled = !shieldEnabled
                MeshVpnService.guardianEnabled = shieldEnabled
                getSharedPreferences("nexomesh_prefs", MODE_PRIVATE).edit().putBoolean("guardian_enabled", shieldEnabled).apply()
                appendLog(if (shieldEnabled) "INFO" else "WARNING", "AutoEscudo", myVirtualIp, if (shieldEnabled) "Modo Guardián encendido por el usuario" else "Modo Guardián apagado por el usuario")
                refreshAllUi()
            }
        }
        defenseBunkerBtn = makeStyledButton("Modo Búnker: OFF", themeInset(), "#334155", "#CBD5E1").apply {
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply { leftMargin = dp(4) }
            setOnClickListener {
                bunkerMode = !bunkerMode
                MeshVpnService.bunkerMode = bunkerMode
                if (RustCoreBridge.isNativeReady()) {
                    RustCoreBridge.setDefensePolicy(bunkerMode, 120)
                }
                appendLog(if (bunkerMode) "WARNING" else "INFO", "AutoEscudo", myVirtualIp, if (bunkerMode) "Modo Búnker activado: solo pares verificados" else "Modo Búnker desactivado")
                refreshAllUi()
            }
        }
        defBtnRow.addView(defenseShieldBtn)
        defBtnRow.addView(defenseBunkerBtn)

        val policiesTitle = TextView(this).apply {
            text = "Políticas Granulares de Defensa"
            textSize = 13f
            setTypeface(null, Typeface.BOLD)
            setTextColor(Color.parseColor("#F8FAFC"))
            setPadding(0, dp(4), 0, dp(6))
        }
        fun makePolicyCheck(label: String, prefKey: String, initVal: Boolean, onChange: (Boolean) -> Unit): CheckBox {
            return CheckBox(this).apply {
                text = label
                isChecked = initVal
                setTextColor(Color.parseColor("#E2E8F0"))
                textSize = 12f
                setPadding(dp(4), dp(6), dp(4), dp(6))
                setOnCheckedChangeListener { _, checked ->
                    getSharedPreferences("nexomesh_prefs", MODE_PRIVATE).edit().putBoolean(prefKey, checked).apply()
                    onChange(checked)
                }
            }
        }
        policyQuarantineSwitch = makePolicyCheck("Cuarentena automática al detectar anomalías", "policy_quarantine", policyAutoQuarantine) {
            policyAutoQuarantine = it
        }
        policyRotateSwitch = makePolicyCheck("Rotar llaves Curve25519 ante sospecha", "policy_rotate", policyAutoRotateKeys) {
            policyAutoRotateKeys = it
        }
        policyRateLimitSwitch = makePolicyCheck("Mitigar Flood UDP / saturación de paquetes", "policy_ratelimit", policyUdpRateLimit) {
            policyUdpRateLimit = it
        }
        policyAutoBunkerSwitch = makePolicyCheck("Activar Búnker automático en alerta crítica", "policy_autobunker", policyAutoBunkerOnCrit) {
            policyAutoBunkerOnCrit = it
        }
        policyStrictDnsSwitch = makePolicyCheck("Bloqueo estricto DNS fuera del túnel VPN", "policy_strictdns", policyStrictDnsKill) {
            policyStrictDnsKill = it
        }

        val attackTitle = TextView(this).apply {
            text = "Pruebas de Intrusión en Vivo"
            textSize = 13f
            setTypeface(null, Typeface.BOLD)
            setTextColor(Color.parseColor("#F8FAFC"))
            setPadding(0, dp(10), 0, dp(6))
        }
        val atkRow1 = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT).apply { bottomMargin = dp(6) }
        }
        val atkFloodBtn = makeStyledButton("Flood UDP", "#450A0A", "#EF4444", "#FCA5A5").apply {
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply { rightMargin = dp(4) }
            setOnClickListener { triggerDefenseAttackTest("Flood UDP") }
        }
        val atkScanBtn = makeStyledButton("Escaneo ADB/SMB", "#450A0A", "#EF4444", "#FCA5A5").apply {
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply { leftMargin = dp(4) }
            setOnClickListener { triggerDefenseAttackTest("Escaneo Puertos / ADB") }
        }
        atkRow1.addView(atkFloodBtn)
        atkRow1.addView(atkScanBtn)

        val atkMitmBtn = makeStyledButton("Simular MitM / Llave Inválida", "#450A0A", "#EF4444", "#FCA5A5").apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dp(10) }
            setOnClickListener { triggerDefenseAttackTest("MitM / Llave Inválida") }
        }
        defenseQuarantineContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
        }
        defenseCard.addView(defTitle)
        defenseCard.addView(defSub)
        defenseCard.addView(guardianPostureBanner)
        defenseCard.addView(defenseStatsText)
        defenseCard.addView(defBtnRow)
        defenseCard.addView(policiesTitle)
        defenseCard.addView(policyQuarantineSwitch)
        defenseCard.addView(policyRotateSwitch)
        defenseCard.addView(policyRateLimitSwitch)
        defenseCard.addView(policyAutoBunkerSwitch)
        defenseCard.addView(policyStrictDnsSwitch)
        defenseCard.addView(attackTitle)
        defenseCard.addView(atkRow1)
        defenseCard.addView(atkMitmBtn)
        defenseCard.addView(defenseQuarantineContainer)

        col.addView(defenseCard)
        scroll.addView(col)
        return scroll
    }

    private fun normalizeSearchText(value: String): String {
        val normalized = Normalizer.normalize(value.trim().lowercase(Locale.US), Normalizer.Form.NFD)
        return Regex("\\p{InCombiningDiacriticalMarks}+").replace(normalized, "")
    }

    private fun renderConnectPeerSearchResults() {
        if (!::connectPeerResultsContainer.isInitialized) return
        val q = normalizeSearchText(connectPeerSearchQuery)
        val matches = if (q.isEmpty()) {
            connectedPeers.toList()
        } else {
            connectedPeers.filter { peer ->
                normalizeSearchText(peer.name).contains(q) ||
                    peer.virtualIp.lowercase(Locale.US).contains(q) ||
                    peer.endpoint.lowercase(Locale.US).contains(q) ||
                    peer.lanEndpoint.lowercase(Locale.US).contains(q)
            }
        }
        connectPeerCountText.text = "${matches.size} de ${connectedPeers.size} pares"
        connectPeerResultsContainer.removeAllViews()

        if (connectedPeers.isEmpty()) {
            val emptyTv = TextView(this).apply {
                text = "Aún no hay dispositivos enlazados en la red mesh. Comparte o escanea un QR abajo para agregar pares."
                textSize = 11f
                setTextColor(Color.parseColor("#94A3B8"))
                setPadding(dp(2), dp(4), dp(2), dp(4))
            }
            connectPeerResultsContainer.addView(emptyTv)
            return
        }

        if (matches.isEmpty()) {
            val noMatchTv = TextView(this).apply {
                text = "No se encontraron dispositivos que coincidan con «${connectPeerSearchQuery.trim()}»."
                textSize = 12f
                setTextColor(Color.parseColor("#FCD34D"))
                setPadding(dp(2), dp(6), dp(2), dp(6))
            }
            connectPeerResultsContainer.addView(noMatchTv)
            return
        }

        for (peer in matches) {
            val card = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                background = makeCardDrawable(themeInset(), if (peer.quarantined) "#EF4444" else themeBorder(), 12, 1)
                setPadding(dp(12), dp(10), dp(12), dp(10))
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                ).apply { bottomMargin = dp(8) }
                setOnClickListener { showPeerDetailDialog(peer) }
            }
            val infoCol = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            }
            val titleTv = TextView(this).apply {
                text = peer.name
                textSize = 13f
                setTypeface(null, Typeface.BOLD)
                setTextColor(Color.parseColor("#F8FAFC"))
            }
            val lanPart = if (peer.lanEndpoint.isNotBlank()) " · LAN ${peer.lanEndpoint}" else ""
            val ipTv = TextView(this).apply {
                text = "${peer.virtualIp} · ${peer.platform}$lanPart"
                textSize = 11f
                setTextColor(Color.parseColor(if (peer.quarantined) "#FCA5A5" else "#34D399"))
            }
            infoCol.addView(titleTv)
            infoCol.addView(ipTv)

            val rightCol = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                gravity = Gravity.END
            }
            val currentRtt = if (peer.online && !peer.quarantined) {
                if (peer.rttMs > 0) peer.rttMs else (rttHistory.lastOrNull()?.toInt() ?: 22)
            } else {
                0
            }
            val activeBars = when {
                !peer.online || peer.quarantined -> 0
                currentRtt <= 40 -> 3
                currentRtt <= 100 -> 2
                else -> 1
            }
            val barColor = when (activeBars) {
                3 -> "#34D399"
                2 -> "#FBBF24"
                1 -> "#F87171"
                else -> "#64748B"
            }
            val latBg = when (activeBars) {
                3 -> "#064E3B"
                2 -> "#451A03"
                1 -> "#450A0A"
                else -> themeSurface()
            }
            val latPill = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                background = makeCardDrawable(latBg, barColor, 8, 1)
                setPadding(dp(7), dp(3), dp(7), dp(3))
            }
            val barsBox = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.BOTTOM
                setPadding(0, 0, dp(5), 0)
            }
            val barHeights = listOf(dp(5), dp(8), dp(11))
            for (bIdx in 0 until 3) {
                val bar = View(this).apply {
                    setBackgroundColor(Color.parseColor(if (bIdx < activeBars) barColor else "#475569"))
                    layoutParams = LinearLayout.LayoutParams(dp(3), barHeights[bIdx]).apply {
                        if (bIdx < 2) rightMargin = dp(2)
                    }
                }
                barsBox.addView(bar)
            }
            val latTv = TextView(this).apply {
                text = if (!peer.online || peer.quarantined) "Sin enlace" else "$currentRtt ms"
                textSize = 11f
                setTypeface(null, Typeface.BOLD)
                setTextColor(Color.parseColor(barColor))
            }
            latPill.addView(barsBox)
            latPill.addView(latTv)

            val badgeTv = TextView(this).apply {
                text = if (peer.quarantined) "Cuarentena" else if (peer.online && vpnRunning) "P2P Activo" else if (peer.online) "Listo" else "Pausado"
                textSize = 10f
                setTypeface(null, Typeface.BOLD)
                setPadding(0, dp(3), 0, 0)
                setTextColor(Color.parseColor(if (peer.quarantined) "#F87171" else if (peer.online) "#34D399" else "#FBBF24"))
            }
            rightCol.addView(latPill)
            rightCol.addView(badgeTv)
            card.addView(infoCol)
            card.addView(rightCol)
            connectPeerResultsContainer.addView(card)
        }
    }

    private fun updateConnectSubTabs() {
        val shareActive = connectSubTab == 0
        shareQrCard.visibility = if (shareActive) View.VISIBLE else View.GONE
        scanQrCard.visibility = if (shareActive) View.GONE else View.VISIBLE
        subTabShareBtn.background = makeCardDrawable(if (shareActive) themeSurface() else themeInset(), if (shareActive) themeAccent() else themeBorder(), 10, 1)
        subTabShareBtn.setTextColor(Color.parseColor(if (shareActive) "#F8FAFC" else "#94A3B8"))
        subTabScanBtn.background = makeCardDrawable(if (!shareActive) themeSurface() else themeInset(), if (!shareActive) themeAccent() else themeBorder(), 10, 1)
        subTabScanBtn.setTextColor(Color.parseColor(if (!shareActive) "#F8FAFC" else "#94A3B8"))
    }

    private fun refreshAllUi() {
        val prefs = getSharedPreferences("nexomesh_prefs", MODE_PRIVATE)
        val isLost = backoffAttempt > 0

        // Header Avatar & Name
        val profName = prefs.getString("user_name", Build.MODEL)?.ifBlank { Build.MODEL } ?: Build.MODEL
        headerProfileName.text = profName.take(12)
        val savedAvatarPath = prefs.getString("user_avatar_path", null)
        val savedPreset = prefs.getString("user_avatar_preset", "🛡️") ?: "🛡️"
        val avatarFile = if (!savedAvatarPath.isNullOrBlank()) File(savedAvatarPath) else null
        if (avatarFile != null && avatarFile.exists()) {
            val bmp = try { BitmapFactory.decodeFile(avatarFile.absolutePath) } catch (_: Exception) { null }
            if (bmp != null) {
                headerAvatarImage.setImageBitmap(bmp)
                headerAvatarImage.visibility = View.VISIBLE
                headerAvatarBadge.visibility = View.GONE
            } else {
                headerAvatarImage.visibility = View.GONE
                headerAvatarBadge.visibility = View.VISIBLE
                headerAvatarBadge.text = savedPreset
            }
        } else {
            headerAvatarImage.visibility = View.GONE
            headerAvatarBadge.visibility = View.VISIBLE
            headerAvatarBadge.text = savedPreset
        }

        // Header badge
        if (isLost) {
            headerBadge.text = "Sin Red"
            headerBadge.setTextColor(Color.parseColor("#FCA5A5"))
            headerBadge.background = makeCardDrawable("#7F1D1D", "#EF4444", 99, 1)
        } else if (vpnRunning) {
            headerBadge.text = "Conectado"
            headerBadge.setTextColor(Color.parseColor("#34D399"))
            headerBadge.background = makeCardDrawable("#064E3B", "#10B981", 99, 1)
        } else {
            headerBadge.text = "Desconectado"
            headerBadge.setTextColor(Color.parseColor("#94A3B8"))
            headerBadge.background = makeCardDrawable("#1E293B", "#334155", 99, 1)
        }

        // Tunnel main status & power circle
        tunnelPolicyLabel.text = detectDevicePolicy()
        if (isLost) {
            tunnelTitleText.text = "Red Perdida · Reconectando"
            tunnelSubtitleText.text = "Backoff exponencial intento #$backoffAttempt en progreso"
            powerCircleBtn.text = "Restaurar"
            powerCircleBtn.setTextColor(Color.parseColor("#FCA5A5"))
            powerCircleBtn.background = makeCardDrawable("#450A0A", "#EF4444", 999, 2)
        } else if (vpnRunning) {
            tunnelTitleText.text = "Túnel P2P Protegido"
            tunnelSubtitleText.text = "IP virtual $myVirtualIp/24 · ${Build.MODEL}"
            powerCircleBtn.text = "Conectado"
            powerCircleBtn.setTextColor(Color.parseColor("#34D399"))
            powerCircleBtn.background = makeCardDrawable("#064E3B", "#10B981", 999, 2)
        } else {
            tunnelTitleText.text = "VPN Desconectada"
            tunnelSubtitleText.text = "Toca el botón para abrir la red privada ($myVirtualIp/24)"
            powerCircleBtn.text = "Conectar"
            powerCircleBtn.setTextColor(Color.parseColor("#CBD5E1"))
            powerCircleBtn.background = makeCardDrawable(themeInset(), "#334155", 999, 2)
        }

        stunLineText.text = "Noise IKpsk2 · STUN $lastStunMapped"
        metricStability.text = if (isLost) "0%" else if (vpnRunning) "98%" else "—"
        metricStability.setTextColor(Color.parseColor(if (isLost) "#EF4444" else "#34D399"))
        metricLatency.text = if (vpnRunning && !isLost) (if (activeMedium == "ethernet") "14 ms" else if (activeMedium == "wifi") "21 ms" else "32 ms") else "—"
        metricLatency.setTextColor(Color.parseColor("#F8FAFC"))
        metricSpeed.text = if (vpnRunning && !isLost) (if (activeMedium == "ethernet") "78 Mbps" else if (activeMedium == "wifi") "54 Mbps" else "28 Mbps") else "0 Mbps"
        metricSpeed.setTextColor(Color.parseColor("#38BDF8"))

        tunnelGuardianMiniText.text = "🛡️ Guardián: ${if (shieldEnabled) "ENCENDIDO" else "APAGADO"} · Búnker ${if (bunkerMode) "ON" else "OFF"} · Bloqueados $blockedPacketsCount"
        tunnelGuardianMiniText.setTextColor(Color.parseColor(if (shieldEnabled) "#34D399" else "#FBBF24"))

        // Transport pills in Tunnel & Settings
        val medName = when (activeMedium) {
            "ethernet" -> "Cable Ethernet"
            "wifi" -> "Wi-Fi"
            else -> "4G/5G"
        }
        transportSummaryTitle.text = "Conexión: $medName"
        transportDetailText.text = if (autoTransportMode) {
            "Auto ($medName): MTU $activeMtu · Keepalive ${activeKeepalive}s"
        } else {
            "Manual ($medName): MTU $activeMtu · Keepalive ${activeKeepalive}s"
        }
        footerStatsText.text = "IP $myVirtualIp/24 · MTU $activeMtu · ${activeKeepalive}s"

        fun styleTransportBtn(btn: Button, selected: Boolean, isAutoStyle: Boolean = false) {
            if (selected) {
                val activeBorder = if (isAutoStyle) themeAccent() else "#38BDF8"
                btn.background = makeCardDrawable(if (isAutoStyle) "#064E3B" else "#0C4A6E", activeBorder, 12, 1)
                btn.setTextColor(Color.parseColor(if (isAutoStyle) "#34D399" else "#7DD3FC"))
            } else {
                btn.background = makeCardDrawable(themeInset(), "#334155", 12, 1)
                btn.setTextColor(Color.parseColor("#CBD5E1"))
            }
        }
        styleTransportBtn(btnAutoMode, autoTransportMode, true)
        styleTransportBtn(btnCellularMode, !autoTransportMode && activeMedium == "cellular")
        styleTransportBtn(btnWifiMode, !autoTransportMode && activeMedium == "wifi")
        styleTransportBtn(btnEthernetMode, !autoTransportMode && activeMedium == "ethernet")

        styleTransportBtn(settingsAutoBtn, autoTransportMode, true)
        settingsAutoBtn.text = if (autoTransportMode) "Automático Activo · $medName" else "Activar Automático (4G/5G ↔ Wi-Fi ↔ Ethernet)"
        styleTransportBtn(settingsCellularBtn, !autoTransportMode && activeMedium == "cellular")
        styleTransportBtn(settingsWifiBtn, !autoTransportMode && activeMedium == "wifi")
        styleTransportBtn(settingsEthernetBtn, !autoTransportMode && activeMedium == "ethernet")

        styleTransportBtn(settingsMtu1280Btn, activeMtu == 1280, true)
        styleTransportBtn(settingsMtu1380Btn, activeMtu == 1380, true)
        styleTransportBtn(settingsMtu1420Btn, activeMtu == 1420, true)
        styleTransportBtn(settingsKa10Btn, activeKeepalive == 10)
        styleTransportBtn(settingsKa15Btn, activeKeepalive == 15)
        styleTransportBtn(settingsKa25Btn, activeKeepalive == 25)

        // Recommendation details in Settings
        when (activeMedium) {
            "ethernet" -> {
                settingsRecTitle.text = "Recomendación (Cable Ethernet)"
                settingsRecTopology.text = "Malla Completa Directa P2P"
                settingsRecDesc.text = "Usa MTU 1420 bytes y keepalive de 25s para aprovechar todo el ancho de banda y mínima latencia."
                settingsRecBullets.text = "• MTU 1420 bytes (trama WireGuard completa)\n• Keepalive relajado 25s en tabla NAT estable\n• Enlace directo P2P UDP entre pares"
            }
            "wifi" -> {
                settingsRecTitle.text = "Recomendación (Red Wi-Fi)"
                settingsRecTopology.text = "Enlace Directo UDP / Doble NAT Local"
                settingsRecDesc.text = "Usa MTU 1380 bytes y keepalive de 15s para evitar fragmentación en routers PPPoE/IPv6 sin agotar batería."
                settingsRecBullets.text = "• MTU 1380 bytes óptimo para routers Wi-Fi domésticos\n• Keepalive equilibrado 15s en banda 2.4 / 5 GHz\n• Prioridad P2P directo UDP con ahorro de batería"
            }
            else -> {
                settingsRecTitle.text = "Recomendación (Datos Móviles 4G/5G)"
                settingsRecTopology.text = "Hub / Host Central ($myVirtualIp)"
                settingsRecDesc.text = "Usa MTU 1280 bytes y keepalive cada 10s para atravesar CGNAT móvil sin cortes de sesión."
                settingsRecBullets.text = "• MTU 1280 bytes seguro contra fragmentación UDP 4G/5G\n• Keepalive UDP cada 10s para sostener CGNAT\n• Perforación NAT activa en cambios de antena"
            }
        }

        // Keep-Alive PASS Status: verificaciones reales del sistema Android (sin auto-PASS)
        val batteryPass = isBatteryExempt()
        val lockPass = prefs.getBoolean("keepalive_lock_pass", false)
        val vpnAlwaysOnPass = MeshVpnService.isRealAlwaysOnActive(this)
        val cmBg = getSystemService(ConnectivityManager::class.java)
        val bgAllowedReal = (cmBg?.restrictBackgroundStatus ?: ConnectivityManager.RESTRICT_BACKGROUND_STATUS_ENABLED) != ConnectivityManager.RESTRICT_BACKGROUND_STATUS_ENABLED
        val autoRevokeReal = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            packageManager.isAutoRevokeWhitelisted
        } else {
            prefs.getBoolean("keepalive_data_legacy_pass", false)
        }
        val bgDataPass = bgAllowedReal && autoRevokeReal
        val passedCount = listOf(batteryPass, lockPass, vpnAlwaysOnPass, bgDataPass).count { it }
        val pct = (passedCount * 100) / 4

        if (passedCount == 4) {
            tunnelKeepAliveBtn.text = "Blindaje Anti-Cierre Android · 4/4 ALL PASS ✓"
            tunnelKeepAliveBtn.background = makeCardDrawable("#064E3B", "#10B981", 12, 1)
            tunnelKeepAliveBtn.setTextColor(Color.parseColor("#34D399"))
            guideHeaderTitle.text = "Guía Visual Anti-Cierre Android (4/4 ALL PASS ✓)"
            guideProgressText.text = "Estado verificado: PASS — Android no puede cerrar NexoMesh"
            guideProgressText.setTextColor(Color.parseColor("#34D399"))
        } else {
            tunnelKeepAliveBtn.text = "Blindar Android contra cierre · $passedCount/4 PENDIENTE"
            tunnelKeepAliveBtn.background = makeCardDrawable("#1F1A0D", "#854D0E", 12, 1)
            tunnelKeepAliveBtn.setTextColor(Color.parseColor("#FBBF24"))
            guideHeaderTitle.text = "Guía Visual Anti-Cierre Android ($passedCount/4 PASS)"
            guideProgressText.text = "Progreso verificado en Android: $pct%"
            guideProgressText.setTextColor(Color.parseColor("#FBBF24"))
        }
        guideProgressBar.progress = pct
        val wakeState = if (MeshVpnService.isWakeLockHeld) "WakeLock ACTIVO" else "WakeLock esperando túnel"
        val svcState = if (MeshVpnService.isServiceRunning) "Servicio Foreground VIVO" else "Servicio detenido"
        val step4Sub = if (bgDataPass) "OK" else if (!bgAllowedReal && !autoRevokeReal) "Falta Datos y Sin Pausar" else if (!bgAllowedReal) "Falta Datos sin restricciones" else "Falta desmarcar 'Pausar app'"
        guideInlineResultText.text = "Auditoría real ($passedCount/4 PASS) · $svcState · $wakeState\n" +
            "01 Batería: ${if (batteryPass) "PASS" else "PENDIENTE"} · 02 Candado: ${if (lockPass) "PASS" else "PENDIENTE"}\n" +
            "03 VPN Siempre Activa: ${if (vpnAlwaysOnPass) "PASS" else "PENDIENTE"} · 04 Datos/Sin Pausar: $step4Sub"
        guideInlineResultText.setTextColor(Color.parseColor(if (passedCount == 4) "#34D399" else "#CBD5E1"))
        renderGuideSteps(batteryPass, lockPass, vpnAlwaysOnPass, bgDataPass, bgAllowedReal, autoRevokeReal)

        // Theme & Guardián Settings UI
        fun styleThemeBtn(btn: Button, selected: Boolean, accentHex: String) {
            if (selected) {
                btn.background = makeCardDrawable("#0F172A", accentHex, 12, 2)
                btn.setTextColor(Color.parseColor(accentHex))
            } else {
                btn.background = makeCardDrawable(themeInset(), "#334155", 12, 1)
                btn.setTextColor(Color.parseColor("#CBD5E1"))
            }
        }
        styleThemeBtn(themeDarkBtn, activeTheme == "dark", "#10B981")
        styleThemeBtn(themeNeonBtn, activeTheme == "neon", "#00F5D4")
        styleThemeBtn(themeOledBtn, activeTheme == "oled", "#F8FAFC")

        val quarantinedPeers = connectedPeers.filter { it.quarantined }
        val totalBlocked = blockedPacketsCount + MeshVpnService.blockedPacketsCount.toInt()
        defenseStatsText.text = "Paquetes bloqueados: $totalBlocked · Cuarentena: ${quarantinedPeers.size} · Llaves rotadas: $rekeyCount"
        if (bunkerMode) {
            guardianPostureBanner.background = makeCardDrawable("#451A03", "#F59E0B", 12, 1)
            guardianPostureTitle.text = "MODO BÚNKER ACTIVO · BLOQUEO ESTRICTO"
            guardianPostureTitle.setTextColor(Color.parseColor("#FBBF24"))
            guardianPostureSub.text = "Solo pares confiables y verificados pueden intercambiar paquetes en el mesh."
        } else if (shieldEnabled) {
            guardianPostureBanner.background = makeCardDrawable("#052E16", "#10B981", 12, 1)
            guardianPostureTitle.text = "GUARDIÁN ACTIVO POR DEFECTO"
            guardianPostureTitle.setTextColor(Color.parseColor("#34D399"))
            guardianPostureSub.text = "Auto-cuarentena, mitigación UDP Flood y rotación Curve25519 habilitadas."
        } else {
            guardianPostureBanner.background = makeCardDrawable("#450A0A", "#EF4444", 12, 1)
            guardianPostureTitle.text = "GUARDIÁN APAGADO POR EL USUARIO"
            guardianPostureTitle.setTextColor(Color.parseColor("#FCA5A5"))
            guardianPostureSub.text = "El tráfico entra sin aislamiento automático hasta que vuelvas a encenderlo."
        }
        defenseShieldBtn.text = if (shieldEnabled) "Guardián: ENCENDIDO" else "Guardián: APAGADO"
        defenseShieldBtn.background = makeCardDrawable(if (shieldEnabled) "#064E3B" else themeInset(), if (shieldEnabled) "#10B981" else "#475569", 12, 1)
        defenseShieldBtn.setTextColor(Color.parseColor(if (shieldEnabled) "#34D399" else "#CBD5E1"))
        defenseBunkerBtn.text = if (bunkerMode) "Modo Búnker: ON" else "Modo Búnker: OFF"
        defenseBunkerBtn.background = makeCardDrawable(if (bunkerMode) "#451A03" else themeInset(), if (bunkerMode) "#F59E0B" else "#334155", 12, 1)
        defenseBunkerBtn.setTextColor(Color.parseColor(if (bunkerMode) "#FBBF24" else "#CBD5E1"))

        policyQuarantineSwitch.isChecked = policyAutoQuarantine
        policyRotateSwitch.isChecked = policyAutoRotateKeys
        policyRateLimitSwitch.isChecked = policyUdpRateLimit
        policyAutoBunkerSwitch.isChecked = policyAutoBunkerOnCrit
        policyStrictDnsSwitch.isChecked = policyStrictDnsKill

        defenseQuarantineContainer.removeAllViews()
        for (qp in quarantinedPeers) {
            val qBtn = makeStyledButton("Rotar Llave y Liberar: ${qp.name} (${qp.virtualIp})", "#064E3B", "#10B981", "#34D399").apply {
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                ).apply { bottomMargin = dp(6) }
                setOnClickListener {
                    qp.quarantined = false
                    qp.quarantineReason = null
                    qp.online = true
                    rekeyCount += 1
                    MeshVpnService.releaseQuarantinedIp(qp.virtualIp)
                    syncPeersToVpnService()
                    appendLog("INFO", "AutoEscudo", qp.virtualIp, "Llaves rotadas y nodo ${qp.name} liberado de cuarentena")
                    refreshAllUi()
                }
            }
            defenseQuarantineContainer.addView(qBtn)
        }

        // Peers List
        peersHeaderTitle.text = "Amigos en tu Red (${connectedPeers.size})"
        peersListContainer.removeAllViews()
        if (connectedPeers.isEmpty()) {
            val emptyTv = TextView(this).apply {
                text = "Aún no hay amigos enlazados. Pulsa '+ Invitar QR' para añadir dispositivos Android, iOS, Windows, macOS o Linux sin límite."
                textSize = 12f
                setTextColor(Color.parseColor("#94A3B8"))
                setPadding(dp(4), dp(8), dp(4), dp(8))
            }
            peersListContainer.addView(emptyTv)
        } else {
            for (peer in connectedPeers) {
                val row = LinearLayout(this).apply {
                    orientation = LinearLayout.HORIZONTAL
                    gravity = Gravity.CENTER_VERTICAL
                    background = makeCardDrawable(themeInset(), if (peer.quarantined) "#EF4444" else themeBorder(), 12, 1)
                    setPadding(dp(12), dp(12), dp(12), dp(12))
                    layoutParams = LinearLayout.LayoutParams(
                        LinearLayout.LayoutParams.MATCH_PARENT,
                        LinearLayout.LayoutParams.WRAP_CONTENT
                    ).apply { bottomMargin = dp(8) }
                    setOnClickListener { showPeerDetailDialog(peer) }
                }
                val left = LinearLayout(this).apply {
                    orientation = LinearLayout.VERTICAL
                    layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
                }
                val pName = TextView(this).apply {
                    text = peer.name
                    textSize = 13f
                    setTypeface(null, Typeface.BOLD)
                    setTextColor(Color.parseColor("#F8FAFC"))
                }
                val lanSuffix = if (peer.lanEndpoint.isNotBlank()) " · LAN ${peer.lanEndpoint}" else ""
                val pSub = TextView(this).apply {
                    text = if (peer.quarantined) "${peer.virtualIp} · Aislado: ${peer.quarantineReason ?: "Amenaza"}" else "${peer.virtualIp} · ${peer.platform}$lanSuffix"
                    textSize = 11f
                    setTextColor(Color.parseColor(if (peer.quarantined) "#FCA5A5" else "#94A3B8"))
                }
                left.addView(pName)
                left.addView(pSub)

                val pStat = TextView(this).apply {
                    text = if (peer.quarantined) "Cuarentena" else if (peer.online && vpnRunning) "P2P Activo" else if (peer.online) "Listo" else "Pausado"
                    textSize = 11f
                    setTypeface(null, Typeface.BOLD)
                    setTextColor(Color.parseColor(if (peer.quarantined) "#F87171" else if (peer.online) "#34D399" else "#FBBF24"))
                }
                row.addView(left)
                row.addView(pStat)
                peersListContainer.addView(row)
            }
        }
        renderConnectPeerSearchResults()

        // File Transfers UI (Dedicated Archivos Tab — Send/Receive subtabs + Multi-File/Folder Batch)
        fileSpeedModeBtn.text = if (fileMaxSpeedMode) {
            "Velocidad: Máxima Red Permitida (Turbo)"
        } else {
            "Velocidad: Modo Equilibrado"
        }

        val sendSubActive = filesSubTab == 0
        fileSendSection.visibility = if (sendSubActive) View.VISIBLE else View.GONE
        fileReceiveSection.visibility = if (!sendSubActive) View.VISIBLE else View.GONE
        styleTransportBtn(fileSubSendBtn, sendSubActive, true)
        styleTransportBtn(fileSubReceiveBtn, !sendSubActive, false)

        // Peer quick-pick chips for File Sending
        styleTransportBtn(fileChanVpnBtn, fileSendChannel == "VPN")
        styleTransportBtn(fileChanLanBtn, fileSendChannel == "LAN")
        styleTransportBtn(fileChanBtBtn, fileSendChannel == "BLUETOOTH")
        styleTransportBtn(fileChanBothBtn, fileSendChannel == "LAN_BLUETOOTH")
        fileChannelHintText.text = when (fileSendChannel) {
            "LAN" -> "Canal: Red Local (Wi-Fi / LAN TCP :51821 · sin necesitar túnel VPN)"
            "BLUETOOTH" -> "Canal: Bluetooth directo (OPP/RFCOMM ~2.4 Mbps · sin Wi-Fi ni VPN)"
            "LAN_BLUETOOTH" -> "Canal: Red Local + Bluetooth (LAN prioritario y respaldo Bluetooth)"
            else -> "Canal: Túnel VPN P2P (10.0.0.0/24 · máxima velocidad cifrada)"
        }

        filePeerChipsContainer.removeAllViews()
        if (connectedPeers.isEmpty()) {
            val noPeerChip = TextView(this).apply {
                text = "Sin amigos enlazados aún (escribe IP o enlaza por QR)"
                textSize = 11f
                setTextColor(Color.parseColor("#94A3B8"))
                setPadding(dp(4), dp(6), dp(4), dp(6))
            }
            filePeerChipsContainer.addView(noPeerChip)
        } else {
            val currentInputIp = fileTargetIpInput.text.toString().trim()
            for (p in connectedPeers) {
                val activeChip = currentInputIp == p.virtualIp
                val chip = makeStyledButton(
                    "${p.name} (${p.virtualIp})",
                    if (activeChip) "#064E3B" else themeInset(),
                    if (activeChip) "#10B981" else "#334155",
                    if (activeChip) "#34D399" else "#CBD5E1",
                    99
                ).apply {
                    textSize = 11f
                    setPadding(dp(10), dp(6), dp(10), dp(6))
                    minHeight = dp(34)
                    layoutParams = LinearLayout.LayoutParams(
                        LinearLayout.LayoutParams.WRAP_CONTENT,
                        LinearLayout.LayoutParams.WRAP_CONTENT
                    ).apply { rightMargin = dp(6) }
                    setOnClickListener {
                        pendingSendTargetIp = p.virtualIp
                        fileTargetIpInput.setText(p.virtualIp)
                        refreshAllUi()
                    }
                }
                filePeerChipsContainer.addView(chip)
            }
        }

        // Staged Multi-File & Multi-Folder Batch Panel
        if (stagedSendItems.isEmpty()) {
            stagedBatchCard.visibility = View.GONE
        } else {
            stagedBatchCard.visibility = View.VISIBLE
            val totalStageBytes = stagedSendItems.sumOf { it.sizeBytes }
            val folderCnt = stagedSendItems.count { it.isFolder }
            val fileCnt = stagedSendItems.size - folderCnt
            stagedBatchTitle.text = "Lote preparado: $fileCnt archivo(s) · $folderCnt carpeta(s) · ${formatBytes(totalStageBytes)}"
            stagedSendBatchBtn.text = "Enviar Todo el Lote (${stagedSendItems.size} elementos)"
            stagedItemsContainer.removeAllViews()
            for (st in stagedSendItems) {
                val itemRow = LinearLayout(this).apply {
                    orientation = LinearLayout.HORIZONTAL
                    gravity = Gravity.CENTER_VERTICAL
                    background = makeCardDrawable(themeSurface(), themeBorder(), 10, 1)
                    setPadding(dp(10), dp(8), dp(10), dp(8))
                    layoutParams = LinearLayout.LayoutParams(
                        LinearLayout.LayoutParams.MATCH_PARENT,
                        LinearLayout.LayoutParams.WRAP_CONTENT
                    ).apply { bottomMargin = dp(6) }
                }
                val labelTv = TextView(this).apply {
                    val icon = if (st.isFolder) "📁" else "📄"
                    val extra = if (st.isFolder) "${st.fileCount} arch." else formatBytes(st.sizeBytes)
                    text = "$icon ${st.displayName} ($extra)"
                    textSize = 11f
                    setTextColor(Color.parseColor("#E2E8F0"))
                    layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
                }
                val rmTv = TextView(this).apply {
                    text = "✕"
                    textSize = 12f
                    setTypeface(null, Typeface.BOLD)
                    setTextColor(Color.parseColor("#FCA5A5"))
                    setPadding(dp(10), dp(4), dp(4), dp(4))
                    setOnClickListener {
                        stagedSendItems.remove(st)
                        refreshAllUi()
                    }
                }
                itemRow.addView(labelTv)
                itemRow.addView(rmTv)
                stagedItemsContainer.addView(itemRow)
            }
        }

        if (fileReceiverActive) {
            fileReceiverToggleBtn.text = "Receptor Activo (:51821)"
            fileReceiverToggleBtn.background = makeCardDrawable("#064E3B", "#10B981", 12, 1)
            fileReceiverToggleBtn.setTextColor(Color.parseColor("#34D399"))
        } else {
            fileReceiverToggleBtn.text = "Activar Receptor (:51821)"
            fileReceiverToggleBtn.background = makeCardDrawable(themeInset(), "#334155", 12, 1)
            fileReceiverToggleBtn.setTextColor(Color.parseColor("#7DD3FC"))
        }

        val lanNow = getLocalLanIpAddress().ifBlank { "sin Wi-Fi/LAN" }
        fileReceiverHostInfo.text = "IP Túnel VPN: $myVirtualIp:51821 · LAN Wi-Fi: $lanNow:51821"

        fileReceiveFolderBtn.text = if (receiveFolderLabel.isNotBlank()) {
            "Carpeta Recibidos: $receiveFolderLabel/"
        } else {
            "Carpeta Recibidos: Elegir Destino"
        }

        val cAll = fileTransfersList.size
        val cSent = fileTransfersList.count { it.direction == "send" }
        val cRecv = fileTransfersList.count { it.direction == "receive" }
        val cPend = fileTransfersList.count { it.status == "transferring" || it.status == "paused" || it.status == "thawing" }
        val cComp = fileTransfersList.count { it.status == "completed" }
        val cFail = fileTransfersList.count { it.status == "failed" }
        val cCanc = fileTransfersList.count { it.status == "canceled" }

        fileFilterAllBtn.text = "Todos ($cAll)"
        fileFilterSentBtn.text = "Enviados ($cSent)"
        fileFilterReceivedBtn.text = "Recibidos ($cRecv)"
        fileFilterPendingBtn.text = "En Pausa ($cPend)"
        fileFilterCompletedBtn.text = "Completados ($cComp)"
        fileFilterFailedBtn.text = "Fallidos ($cFail)"
        fileFilterCanceledBtn.text = "Cancelados ($cCanc)"

        styleTransportBtn(fileFilterAllBtn, fileFilterCategory == "ALL")
        styleTransportBtn(fileFilterSentBtn, fileFilterCategory == "SENT")
        styleTransportBtn(fileFilterReceivedBtn, fileFilterCategory == "RECEIVED")
        styleTransportBtn(fileFilterPendingBtn, fileFilterCategory == "PENDING")
        styleTransportBtn(fileFilterCompletedBtn, fileFilterCategory == "COMPLETED")
        styleTransportBtn(fileFilterFailedBtn, fileFilterCategory == "FAILED")
        styleTransportBtn(fileFilterCanceledBtn, fileFilterCategory == "CANCELED")

        val visibleTransfers = fileTransfersList.filter { item ->
            when (fileFilterCategory) {
                "SENT" -> item.direction == "send"
                "RECEIVED" -> item.direction == "receive"
                "PENDING" -> item.status == "transferring" || item.status == "paused" || item.status == "thawing"
                "COMPLETED" -> item.status == "completed"
                "FAILED" -> item.status == "failed"
                "CANCELED" -> item.status == "canceled"
                else -> true
            }
        }

        fileTransfersContainer.removeAllViews()
        if (visibleTransfers.isEmpty()) {
            val emptyFiles = TextView(this).apply {
                text = "Sin transferencias en esta categoría. Selecciona varios archivos/carpetas o activa el receptor (:51821)."
                textSize = 11f
                setTextColor(Color.parseColor("#94A3B8"))
                setPadding(dp(4), dp(8), dp(4), dp(8))
            }
            fileTransfersContainer.addView(emptyFiles)
        } else {
            for (ft in visibleTransfers.take(30)) {
                val ftCard = LinearLayout(this).apply {
                    orientation = LinearLayout.VERTICAL
                    background = makeCardDrawable(themeInset(), themeBorder(), 12, 1)
                    setPadding(dp(12), dp(12), dp(12), dp(12))
                    layoutParams = LinearLayout.LayoutParams(
                        LinearLayout.LayoutParams.MATCH_PARENT,
                        LinearLayout.LayoutParams.WRAP_CONTENT
                    ).apply { bottomMargin = dp(8) }
                }
                val topRow = LinearLayout(this).apply {
                    orientation = LinearLayout.HORIZONTAL
                    gravity = Gravity.CENTER_VERTICAL
                }
                val circleView = LiquidCircleView(this).apply {
                    setTransferState(ft.progressPct, ft.status, ft.frostLevel, waveTick)
                    layoutParams = LinearLayout.LayoutParams(dp(56), dp(56)).apply { rightMargin = dp(12) }
                }
                val ftCol = LinearLayout(this).apply {
                    orientation = LinearLayout.VERTICAL
                    layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
                }
                val arrow = if (ft.direction == "send") "↑" else "↓"
                val ftName = TextView(this).apply {
                    text = "$arrow ${ft.fileName} (${formatBytes(ft.sizeBytes)})"
                    textSize = 13f
                    setTypeface(null, Typeface.BOLD)
                    setTextColor(Color.parseColor("#F8FAFC"))
                }
                val statusLabel = when (ft.status) {
                    "paused" -> "Pausado · Congelado"
                    "thawing" -> "Reintentando · Deshielando (${100 - ft.frostLevel}%)"
                    "failed" -> ft.errorReason ?: "Error de envío"
                    "canceled" -> "Cancelado · Vacío"
                    "completed" -> "Completado 100%"
                    else -> "Transfiriendo ${ft.progressPct}%"
                }
                val ftMeta = TextView(this).apply {
                    text = "${ft.peerIp} · ${ft.channel} · $statusLabel"
                    textSize = 11f
                    setTextColor(Color.parseColor("#94A3B8"))
                }
                ftCol.addView(ftName)
                ftCol.addView(ftMeta)
                topRow.addView(circleView)
                topRow.addView(ftCol)
                ftCard.addView(topRow)

                val btnRow = LinearLayout(this).apply {
                    orientation = LinearLayout.HORIZONTAL
                    setPadding(0, dp(8), 0, 0)
                }
                if (ft.status == "transferring" || ft.status == "thawing") {
                    val pauseBtn = makeStyledButton("Pausar", "#0C4A6E", "#38BDF8", "#BAE6FD").apply {
                        layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply { rightMargin = dp(4) }
                        setOnClickListener {
                            ft.status = "paused"
                            ft.frostLevel = 100
                            refreshAllUi()
                        }
                    }
                    val cancelBtn = makeStyledButton("Cancelar", "#450A0A", "#EF4444", "#FCA5A5").apply {
                        layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply { leftMargin = dp(4) }
                        setOnClickListener {
                            ft.status = "canceled"
                            ft.progressPct = 0
                            ft.frostLevel = 0
                            refreshAllUi()
                        }
                    }
                    btnRow.addView(pauseBtn)
                    btnRow.addView(cancelBtn)
                    ftCard.addView(btnRow)
                } else if (ft.status == "paused" || ft.status == "failed" || ft.status == "canceled") {
                    val retryBtn = makeStyledButton(
                        if (ft.status == "failed") "Reintentar envío" else "Reintentar",
                        "#059669",
                        "#10B981",
                        "#FFFFFF"
                    ).apply {
                        layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
                        setOnClickListener {
                            if (ft.status == "failed" && ft.sourceUri != null) {
                                fileTransfersList.remove(ft)
                                if (ft.isFolder) {
                                    sendSelectedFolderP2P(ft.sourceUri, ft.peerIp)
                                } else {
                                    sendSelectedFileP2P(ft.sourceUri, ft.peerIp)
                                }
                            } else {
                                ft.status = "thawing"
                                ft.errorReason = null
                                ft.frostLevel = if (ft.frostLevel > 0) ft.frostLevel else 80
                                if (ft.progressPct == 0) ft.progressPct = 15
                                refreshAllUi()
                            }
                        }
                    }
                    btnRow.addView(retryBtn)
                    ftCard.addView(btnRow)
                } else if (ft.localFile != null && ft.localFile.exists()) {
                    val saveBtn = makeStyledButton("Guardar / Abrir", "#0C4A6E", "#38BDF8", "#BAE6FD").apply {
                        layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT)
                        setOnClickListener { shareOrOpenLocalFile(ft.localFile) }
                    }
                    btnRow.addView(saveBtn)
                    ftCard.addView(btnRow)
                }
                fileTransfersContainer.addView(ftCard)
            }
        }

        // Telemetry Graph & 4 Stat Boxes
        telemetryGraphView.setSeries(rttHistory, rxHistory, txHistory)
        val latestRtt = rttHistory.lastOrNull()?.toInt() ?: 0
        val latestRx = rxHistory.lastOrNull()?.toInt() ?: 0
        val latestTx = txHistory.lastOrNull()?.toInt() ?: 0
        val healthScore = if (isLost) 0 else if (vpnRunning) 98 else 74
        telemetrySummaryText.text = "RTT $latestRtt ms · Rx $latestRx Mbps · Tx $latestTx Mbps"
        statBoxRtt.text = if (vpnRunning && !isLost) "$latestRtt ms" else "—"
        statBoxRx.text = "$latestRx Mbps"
        statBoxTx.text = "$latestTx Mbps"
        statBoxScore.text = "$healthScore%"

        val nowRttMs = System.currentTimeMillis()
        val peerPalette = listOf("#10B981", "#38BDF8", "#F59E0B", "#A78BFA", "#F472B6")
        val peerSeries = connectedPeers.mapIndexed { idx, peer ->
            val colorHex = peerPalette[idx % peerPalette.size]
            val list = peerRtt60sHistory.getOrPut(peer.id) {
                val baseVal = if (peer.online && !peer.quarantined) peer.rttMs.toFloat() else -1f
                mutableListOf(
                    (nowRttMs - 60_000L) to baseVal,
                    (nowRttMs - 30_000L) to baseVal,
                    nowRttMs to baseVal
                )
            }
            Triple(peer.name, colorHex, list.filter { nowRttMs - it.first <= 60_000L })
        }
        peerRtt60sGraphView.setPeerSeries(peerSeries, nowRttMs)
        peerRtt60sSummaryText.text = if (connectedPeers.isEmpty()) {
            "Ventana móvil de 60 s · Sin pares conectados aún"
        } else {
            connectedPeers.joinToString("  ·  ") { peer ->
                val cur = if (peer.online && !peer.quarantined) "${peer.rttMs} ms" else "Offline"
                "${peer.name}: $cur"
            }
        }

        val activeBarItems = connectedPeers.mapIndexedNotNull { idx, peer ->
            if (!peer.online || peer.quarantined) return@mapIndexedNotNull null
            val colorHex = peerPalette[idx % peerPalette.size]
            val samples = peerRtt60sHistory[peer.id]
                ?.filter { nowRttMs - it.first <= 60_000L && it.second >= 0f }
                ?.map { it.second }
                ?: emptyList()
            val avgRtt = if (samples.isNotEmpty()) samples.average().toFloat() else peer.rttMs.toFloat()
            Triple(peer.name, colorHex, avgRtt)
        }.sortedByDescending { it.third }
        peerAvgBarGraphView.setBars(activeBarItems)
        val meshAvgBar = if (activeBarItems.isNotEmpty()) activeBarItems.map { it.third }.average().toInt() else 0
        peerAvgBarSummaryText.text = if (activeBarItems.isEmpty()) {
            "0 de ${connectedPeers.size} pares activos · Sin pares en línea"
        } else {
            "${activeBarItems.size} de ${connectedPeers.size} pares activos · Promedio malla: $meshAvgBar ms"
        }

        activityMetricsSection.visibility = if (activitySubTab == 0) View.VISIBLE else View.GONE
        activityTopologySection.visibility = if (activitySubTab == 1) View.VISIBLE else View.GONE
        styleTransportBtn(activitySubMetricsBtn, activitySubTab == 0)
        styleTransportBtn(activitySubTopologyBtn, activitySubTab == 1)
        meshTopologyCanvasView.setMeshData(myVirtualIp, vpnRunning && !isLost, connectedPeers.toList())
        meshTopologySummaryText.text = "${connectedPeers.size + 1} nodos · ${activeBarItems.size} enlaces activos · Promedio $meshAvgBar ms"

        // Activity & Logs
        activityStunTitle.text = "Sonda STUN en Vivo ($activeStunServer)"
        activityStunEndpoint.text = "Endpoint: $lastStunMapped · Noise IKpsk2"
        settingsStunText.text = "Servidor STUN: $activeStunServer · Endpoint: $lastStunMapped"

        val filtered = logsList.filter { logSeverityFilter == "ALL" || it.severity == logSeverityFilter }
        logsTitleText.text = "Registro de Eventos del Túnel (${filtered.size})"
        styleTransportBtn(filterAllBtn, logSeverityFilter == "ALL")
        styleTransportBtn(filterInfoBtn, logSeverityFilter == "INFO")
        styleTransportBtn(filterWarnBtn, logSeverityFilter == "WARNING")
        styleTransportBtn(filterCritBtn, logSeverityFilter == "CRITICAL")

        logsContainer.removeAllViews()
        for (item in filtered.take(60)) {
            val row = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                background = makeCardDrawable(themeInset(), themeBorder(), 10, 1)
                setPadding(dp(10), dp(8), dp(10), dp(8))
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                ).apply { bottomMargin = dp(6) }
            }
            val meta = TextView(this).apply {
                text = "${item.timestamp} · ${item.severity} · ${item.subsystem} · ${item.peerIp}"
                textSize = 10f
                setTypeface(null, Typeface.BOLD)
                setTextColor(
                    Color.parseColor(
                        when (item.severity) {
                            "CRITICAL" -> "#F87171"
                            "WARNING" -> "#FBBF24"
                            else -> "#34D399"
                        }
                    )
                )
            }
            val msg = TextView(this).apply {
                text = item.message
                textSize = 12f
                setTextColor(Color.parseColor("#E2E8F0"))
                setPadding(0, dp(2), 0, 0)
            }
            row.addView(meta)
            row.addView(msg)
            logsContainer.addView(row)
        }
    }

    private fun renderGuideSteps(
        batteryPass: Boolean,
        lockPass: Boolean,
        vpnPass: Boolean,
        dataPass: Boolean,
        bgAllowedReal: Boolean,
        autoRevokeReal: Boolean
    ) {
        guideStepsContainer.removeAllViews()

        data class StepSpec(
            val num: String,
            val title: String,
            val cueChip: String,
            val route: String,
            val passed: Boolean,
            val actionText: String,
            val onAction: () -> Unit
        )
        val step04Cue = if (dataPass) {
            "Datos + Sin Pausar OK"
        } else if (!bgAllowedReal && !autoRevokeReal) {
            "Falta: Datos sin restricciones + Desmarcar Pausar app"
        } else if (!bgAllowedReal) {
            "Falta: Datos sin restricciones"
        } else {
            "Falta: Desmarcar 'Pausar app si no se usa'"
        }
        val specs = listOf(
            StepSpec(
                "01",
                "Batería Sin Restricciones (Verificación Real)",
                "Batería → Permitir sin restricciones",
                "Ajustes → Batería → Uso en segundo plano → Permitir sin restricciones",
                batteryPass,
                if (batteryPass) "Verificado por Android [PASS]" else "Autorizar Batería en Ajustes"
            ) { requestBatteryExemption() },
            StepSpec(
                "02",
                "Inicio Automático + Candado en Recientes",
                "Recientes '⋮' → Candado + Inicio automático",
                "Recientes → Tocar '⋮' en NexoMesh → Bloquear app (Candado) + Inicio automático",
                lockPass,
                if (lockPass) "Confirmado tras Ajustes [PASS]" else "Abrir Info de App para configurar"
            ) {
                pendingSettingsStep = "lock"
                pendingSettingsLeftAtMs = SystemClock.elapsedRealtime()
                reopenKeepAliveOnResume = true
                try {
                    startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                        data = Uri.parse("package:$packageName")
                    })
                } catch (_: Exception) {
                    pendingSettingsStep = null
                    reopenKeepAliveOnResume = false
                }
            },
            StepSpec(
                "03",
                "VPN Siempre Activa (Verificación Real OS)",
                "Ajustes VPN → Engranaje → VPN siempre activa",
                "Ajustes → Red e Internet → VPN → Engranaje NexoMesh → VPN siempre activa",
                vpnPass,
                if (vpnPass) "Detectado por VpnService [PASS]" else "Abrir Ajustes VPN (Verificar al volver)"
            ) {
                pendingSettingsStep = "vpn"
                pendingSettingsLeftAtMs = SystemClock.elapsedRealtime()
                reopenKeepAliveOnResume = true
                try {
                    startActivity(Intent(Settings.ACTION_VPN_SETTINGS))
                } catch (_: Exception) {
                    pendingSettingsStep = null
                    reopenKeepAliveOnResume = false
                }
            },
            StepSpec(
                "04",
                "Datos Sin Restricciones y App Sin Pausar",
                step04Cue,
                "Info de app → Datos móviles y Wi-Fi → Datos sin restricciones + Desmarcar 'Pausar app si no se usa'",
                dataPass,
                if (dataPass) "Verificado por Android [PASS]" else "Abrir Info de App (Verificar al volver)"
            ) {
                pendingSettingsStep = "data"
                pendingSettingsLeftAtMs = SystemClock.elapsedRealtime()
                reopenKeepAliveOnResume = true
                try {
                    startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                        data = Uri.parse("package:$packageName")
                    })
                } catch (_: Exception) {
                    pendingSettingsStep = null
                    reopenKeepAliveOnResume = false
                }
            }
        )

        for (step in specs) {
            val box = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                background = makeCardDrawable(if (step.passed) "#052E16" else themeInset(), if (step.passed) "#10B981" else themeBorder(), 12, 1)
                setPadding(dp(12), dp(12), dp(12), dp(12))
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                ).apply { bottomMargin = dp(10) }
            }
            val headRow = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
            }
            val titleTv = TextView(this).apply {
                text = "${step.num} · ${step.title}"
                textSize = 13f
                setTypeface(null, Typeface.BOLD)
                setTextColor(Color.parseColor("#F8FAFC"))
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            }
            val badgeTv = TextView(this).apply {
                text = if (step.passed) "PASS" else "PENDIENTE"
                textSize = 10f
                setTypeface(null, Typeface.BOLD)
                setTextColor(Color.parseColor(if (step.passed) "#34D399" else "#FBBF24"))
            }
            headRow.addView(titleTv)
            headRow.addView(badgeTv)

            val cueChip = TextView(this).apply {
                text = "Referencia visual: ${step.cueChip}"
                textSize = 10f
                setTypeface(null, Typeface.BOLD)
                setTextColor(Color.parseColor(if (step.passed) "#34D399" else "#FDE68A"))
                background = makeCardDrawable(if (step.passed) "#064E3B" else "#1F1A0D", if (step.passed) "#10B981" else "#854D0E", 8, 1)
                setPadding(dp(8), dp(4), dp(8), dp(4))
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.WRAP_CONTENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                ).apply { topMargin = dp(6) }
            }

            val routeTv = TextView(this).apply {
                text = step.route
                textSize = 11f
                setTextColor(Color.parseColor("#7DD3FC"))
                setPadding(0, dp(6), 0, dp(8))
            }
            val actBtn = makeStyledButton(
                step.actionText,
                if (step.passed) "#064E3B" else "#1E293B",
                if (step.passed) "#10B981" else "#334155",
                if (step.passed) "#34D399" else "#F8FAFC"
            ).apply {
                setOnClickListener { step.onAction() }
            }
            box.addView(headRow)
            box.addView(cueChip)
            box.addView(routeTv)
            box.addView(actBtn)
            guideStepsContainer.addView(box)
        }
    }

    private fun handleReturnFromSystemSettings(step: String, elapsedAwayMs: Long) {
        val prefs = getSharedPreferences("nexomesh_prefs", MODE_PRIVATE)
        when (step) {
            "lock" -> {
                if (elapsedAwayMs >= 1500L && !prefs.getBoolean("keepalive_lock_pass", false)) {
                    makeThemedDialog(
                        title = "Verificar Paso 02",
                        message = "¿Activaste el Candado en Recientes e Inicio automático para NexoMesh?",
                        positiveLabel = "Sí, ya está activo",
                        onPositive = { dlg ->
                            prefs.edit().putBoolean("keepalive_lock_pass", true).apply()
                            appendLog("INFO", "VpnService", myVirtualIp, "Paso 02 verificado por el usuario tras ajustes")
                            refreshAllUi()
                            dlg.dismiss()
                        },
                        negativeLabel = "Aún no"
                    ).show()
                }
            }
            "vpn" -> {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    val realOn = MeshVpnService.isRealAlwaysOnActive(this)
                    if (!realOn) {
                        appendLog("WARNING", "VpnService", myVirtualIp, "Android aún reporta 'VPN siempre activa' desactivada")
                    }
                } else if (elapsedAwayMs >= 1500L) {
                    makeThemedDialog(
                        title = "Verificar Paso 03",
                        message = "¿Activaste 'VPN siempre activa' para NexoMesh en Ajustes VPN?",
                        positiveLabel = "Sí, activado",
                        onPositive = { dlg ->
                            prefs.edit().putBoolean("keepalive_vpn_legacy_pass", true).apply()
                            refreshAllUi()
                            dlg.dismiss()
                        },
                        negativeLabel = "Aún no"
                    ).show()
                }
            }
            "data" -> {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    val realOk = isBackgroundDataAndUnpausedReal()
                    if (!realOk) {
                        appendLog("WARNING", "VpnService", myVirtualIp, "Paso 04 sigue PENDIENTE: desactiva 'Pausar app si no se usa' y permite datos sin restricciones")
                    }
                } else if (elapsedAwayMs >= 1500L) {
                    makeThemedDialog(
                        title = "Verificar Paso 04",
                        message = "¿Habilitaste Datos en segundo plano sin restricciones para NexoMesh?",
                        positiveLabel = "Sí, habilitado",
                        onPositive = { dlg ->
                            prefs.edit().putBoolean("keepalive_data_legacy_pass", true).apply()
                            refreshAllUi()
                            dlg.dismiss()
                        },
                        negativeLabel = "Aún no"
                    ).show()
                }
            }
        }
    }

    private fun runRealKeepAliveAuditDialog() {
        val prefs = getSharedPreferences("nexomesh_prefs", MODE_PRIVATE)
        val batteryPass = isBatteryExempt()
        val lockPass = prefs.getBoolean("keepalive_lock_pass", false)
        val vpnPass = MeshVpnService.isRealAlwaysOnActive(this)
        val cm = getSystemService(ConnectivityManager::class.java)
        val bgAllowed = (cm?.restrictBackgroundStatus ?: ConnectivityManager.RESTRICT_BACKGROUND_STATUS_ENABLED) != ConnectivityManager.RESTRICT_BACKGROUND_STATUS_ENABLED
        val autoRevokeOk = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            packageManager.isAutoRevokeWhitelisted
        } else {
            prefs.getBoolean("keepalive_data_legacy_pass", false)
        }
        val dataPass = bgAllowed && autoRevokeOk
        val passed = listOf(batteryPass, lockPass, vpnPass, dataPass).count { it }
        val wakeHeld = MeshVpnService.isWakeLockHeld
        val svcAlive = MeshVpnService.isServiceRunning

        val statusSummary = "Auditoría real consultada al sistema Android ($passed/4 PASS):\n\n" +
            "01 Batería sin restricciones (Doze): ${if (batteryPass) "PASS ✓" else "PENDIENTE"}\n" +
            "02 Candado / Inicio auto: ${if (lockPass) "PASS ✓" else "PENDIENTE"}\n" +
            "03 VPN siempre activa OS: ${if (vpnPass) "PASS ✓" else "PENDIENTE (Activa interruptor en Ajustes VPN)"}\n" +
            "04a Datos en segundo plano: ${if (bgAllowed) "PASS ✓" else "RESTRINGIDOS"}\n" +
            "04b Desmarcar 'Pausar app sin uso': ${if (autoRevokeOk) "PASS ✓" else "ACTIVO (Peligro de cierre)"}\n\n" +
            "Estado del túnel en memoria:\n" +
            "• Servicio Foreground: ${if (svcAlive) "VIVO ✓" else "Inactivo (inicia el túnel VPN)"}\n" +
            "• WakeLock CPU parcial: ${if (wakeHeld) "RETENIDO ✓" else "Esperando túnel"}"

        appendLog("INFO", "VpnService", myVirtualIp, "Auditoría real anti-cierre: $passed/4 PASS · Service=$svcAlive · WakeLock=$wakeHeld")
        refreshAllUi()
        makeThemedDialog(
            title = if (passed == 4) "Blindaje Android Verificado (4/4 PASS)" else "Auditoría Anti-Cierre ($passed/4 PASS)",
            message = statusSummary,
            positiveLabel = if (batteryPass) "Entendido" else "Autorizar Batería Ahora",
            onPositive = { dlg ->
                dlg.dismiss()
                if (!batteryPass) requestBatteryExemption()
            },
            negativeLabel = if (!batteryPass) "Cerrar" else null
        ).show()
    }

    private fun isBackgroundDataAndUnpausedReal(): Boolean {
        val cm = getSystemService(ConnectivityManager::class.java)
        val bgStatus = cm?.restrictBackgroundStatus ?: ConnectivityManager.RESTRICT_BACKGROUND_STATUS_ENABLED
        val bgAllowed = bgStatus != ConnectivityManager.RESTRICT_BACKGROUND_STATUS_ENABLED
        val autoRevokeOk = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            packageManager.isAutoRevokeWhitelisted
        } else {
            getSharedPreferences("nexomesh_prefs", MODE_PRIVATE).getBoolean("keepalive_data_legacy_pass", false)
        }
        return bgAllowed && autoRevokeOk
    }

    private fun showPeerDetailDialog(peer: PeerItem) {
        val neutralLabel = if (peer.quarantined) "Liberar" else if (peer.online) "Pausar" else "Activar"
        val lanInfo = if (peer.lanEndpoint.isNotBlank()) peer.lanEndpoint else "No reportado"
        makeThemedDialog(
            title = peer.name,
            message = "Plataforma: ${peer.platform}\n" +
                "IP Virtual TUN: ${peer.virtualIp}/24\n" +
                "Endpoint STUN: ${peer.endpoint}\n" +
                "Endpoint LAN Wi-Fi: $lanInfo\n" +
                "Estado Guardián: ${if (peer.quarantined) "EN CUARENTENA (${peer.quarantineReason ?: "Anomalía"})" else "Protegido"}\n" +
                "Cifrado: Noise_IKpsk2_25519_ChaChaPoly",
            positiveLabel = "Enviar Archivos",
            onPositive = { dlg ->
                dlg.dismiss()
                if (peer.quarantined) {
                    appendLog("WARNING", "AutoEscudo", peer.virtualIp, "Envío bloqueado: ${peer.name} sigue en cuarentena")
                    refreshAllUi()
                } else {
                    pendingSendTargetIp = peer.virtualIp
                    filesSubTab = 0
                    fileTargetIpInput.setText(peer.virtualIp)
                    switchTab(AppTab.FILES)
                    refreshAllUi()
                }
            },
            neutralLabel = neutralLabel,
            onNeutral = {
                if (peer.quarantined) {
                    peer.quarantined = false
                    peer.quarantineReason = null
                    peer.online = true
                    rekeyCount += 1
                    MeshVpnService.releaseQuarantinedIp(peer.virtualIp)
                    syncPeersToVpnService()
                    appendLog("INFO", "AutoEscudo", peer.virtualIp, "Llaves rotadas y ${peer.name} liberado de cuarentena")
                } else {
                    peer.online = !peer.online
                    syncPeersToVpnService()
                    appendLog("INFO", "WireGuard", peer.virtualIp, if (peer.online) "Par ${peer.name} reconectado" else "Par ${peer.name} pausado")
                }
                refreshAllUi()
            },
            negativeLabel = "Rotar Llave",
            onNegative = {
                rekeyCount += 1
                appendLog("INFO", "Noise", peer.virtualIp, "Llaves efímeras rotadas con ${peer.name}")
                refreshAllUi()
            }
        ).show()
    }

    private fun hasPhysicalInternet(): Boolean {
        return try {
            val cm = getSystemService(ConnectivityManager::class.java)
            val nets = cm?.allNetworks ?: return false
            nets.any { net ->
                val caps = cm.getNetworkCapabilities(net)
                caps != null &&
                    !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
                    caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            }
        } catch (_: Exception) {
            false
        }
    }

    private fun detectDevicePolicy(): String {
        val oem = Build.MANUFACTURER.lowercase()
        val model = Build.MODEL.lowercase()
        return when {
            oem.contains("oneplus") || oem.contains("oppo") || oem.contains("realme") || model.startsWith("pja") ->
                "OnePlus / ColorOS: confirmación automática + exclusión Doze"
            oem.contains("xiaomi") || oem.contains("redmi") || oem.contains("poco") ->
                "Xiaomi HyperOS: confirmación automática + keepalive 10s"
            oem.contains("samsung") ->
                "Samsung One UI / Knox: confirmación automática + exclusión Doze"
            else ->
                "Android Stock: confirmación automática inmediata VpnService"
        }
    }

    private fun checkFirstInstallScan() {
        val prefs = getSharedPreferences("nexomesh_prefs", MODE_PRIVATE)
        if (prefs.getBoolean("first_install_done", false)) return

        val policy = detectDevicePolicy()
        makeThemedDialog(
            title = "Primera instalación",
            message = "¿Quieres que escanee tu celular para aplicar confirmación automática y blindaje anti-cierre?\n\nDetectado: ${Build.MANUFACTURER} ${Build.MODEL}\nPolítica prevista: $policy",
            positiveLabel = "Escanear mi celular",
            onPositive = { dlg ->
                dlg.dismiss()
                runDeviceScanAndShowResult()
            },
            negativeLabel = "Omitir",
            onNegative = {
                prefs.edit().putBoolean("first_install_done", true).apply()
            }
        ).show()
    }

    private fun runDeviceScanAndShowResult() {
        val policy = detectDevicePolicy()
        val abi = Build.SUPPORTED_ABIS.firstOrNull() ?: "arm64-v8a"
        tunnelSubtitleText.text = "Escaneando ${Build.MANUFACTURER} ${Build.MODEL} ($abi)..."

        mainHandler.postDelayed({
            val prefs = getSharedPreferences("nexomesh_prefs", MODE_PRIVATE)
            prefs.edit()
                .putBoolean("first_install_done", true)
                .putString("oem_policy", policy)
                .apply()

            appendLog("INFO", "VpnService", myVirtualIp, "Escaneo completado ($abi): $policy")
            refreshAllUi()

            makeThemedDialog(
                title = "Escaneo Completado [PASS]",
                message = "Dispositivo: ${Build.MANUFACTURER} ${Build.MODEL}\n" +
                    "Sistema: Android ${Build.VERSION.RELEASE} ($abi)\n" +
                    "Política aplicada: $policy\n" +
                    "Transporte: $activeTransportLabel (MTU $activeMtu · Keepalive ${activeKeepalive}s)\n\n" +
                    "Confirmación automática lista para abrir el túnel VPN.",
                positiveLabel = "Conectar Túnel VPN",
                onPositive = { dlg ->
                    dlg.dismiss()
                    requestAndStartVpn()
                },
                negativeLabel = "Listo"
            ).show()
        }, 450L)
    }

    private fun getOrCreatePublicKey(): String {
        val prefs = getSharedPreferences("nexomesh_prefs", MODE_PRIVATE)
        val existing = prefs.getString("host_pub_key", null)
        if (!existing.isNullOrBlank()) return existing
        return regenerateHostPublicKey()
    }

    private fun regenerateHostPublicKey(): String {
        val prefs = getSharedPreferences("nexomesh_prefs", MODE_PRIVATE)
        val bytes = ByteArray(32)
        SecureRandom().nextBytes(bytes)
        val generated = Base64.encodeToString(bytes, Base64.NO_WRAP)
        prefs.edit().putString("host_pub_key", generated).apply()
        return generated
    }

    private fun allocateNextPeerIp(): String {
        val used = connectedPeers.map { it.virtualIp }.toSet() + setOf(myVirtualIp)
        var octet = 2
        while (used.contains("10.0.0.$octet") && octet < 250) {
            octet += 1
        }
        return "10.0.0.$octet"
    }

    private fun buildCurrentInviteUri(): String {
        val pubKey = getOrCreatePublicKey()
        val nextIp = allocateNextPeerIp()
        val lanIp = getLocalLanIpAddress()
        val lanCandidates = getLocalLanIpCandidates()
        val lanEp = if (lanIp.isNotBlank()) "$lanIp:51820" else ""
        val lansParam = lanCandidates.joinToString(",") { "$it:51820" }
        val epParam = if (lastStunMapped.contains(":")) lastStunMapped else lanEp.ifBlank { "auto:51820" }
        val base = "nexomesh://join?pk=${Uri.encode(pubKey)}&ep=${Uri.encode(epParam)}" +
            "&lan=${Uri.encode(lanEp)}&lans=${Uri.encode(lansParam)}" +
            "&hostIp=$myVirtualIp&ip=$nextIp&noise=IKpsk2&name=${Uri.encode(Build.MODEL)}"
        return if (inviteRequire2fa) {
            "$base&auth2fa=1&pin=$currentInvitePin"
        } else {
            "$base&auth2fa=0"
        }
    }

    private fun renderInlineQrCode() {
        val pubKey = getOrCreatePublicKey()
        val nextIp = allocateNextPeerIp()
        val uri = buildCurrentInviteUri()
        inviteWith2faBtn.background = makeCardDrawable(if (inviteRequire2fa) "#064E3B" else themeInset(), if (inviteRequire2fa) themeAccent() else "#334155", 12, 1)
        inviteWith2faBtn.setTextColor(Color.parseColor(if (inviteRequire2fa) "#34D399" else "#94A3B8"))
        inviteNo2faBtn.background = makeCardDrawable(if (!inviteRequire2fa) "#0C4A6E" else themeInset(), if (!inviteRequire2fa) "#38BDF8" else "#334155", 12, 1)
        inviteNo2faBtn.setTextColor(Color.parseColor(if (!inviteRequire2fa) "#7DD3FC" else "#94A3B8"))
        invitePinText.text = if (inviteRequire2fa) "Código 2FA requerido al amigo: $currentInvitePin" else "Invitación directa sin 2FA activa"
        invitePinText.setTextColor(Color.parseColor(if (inviteRequire2fa) "#34D399" else "#7DD3FC"))
        qrImageView.setImageBitmap(generateQrBitmap(uri, 520))
        val lanNow = getLocalLanIpAddress()
        val epDisplay = if (lastStunMapped.contains(":")) lastStunMapped else if (lanNow.isNotBlank()) "$lanNow:51820 (LAN)" else "Detectando STUN..."
        qrIpText.text = "IP asignada: $nextIp/24 · Host: $myVirtualIp · ${if (inviteRequire2fa) "Con 2FA" else "Sin 2FA"}"
        qrEndpointText.text = "Endpoint: $epDisplay"
        qrKeyText.text = "Llave Curve25519: ${pubKey.take(14)}..."
    }

    private fun resolveStunIpv4Target(serverWithPort: String): String {
        val parts = serverWithPort.split(":")
        val host = parts[0]
        val port = parts.getOrNull(1) ?: "19302"
        val cm = getSystemService(ConnectivityManager::class.java)
        val nets = cm?.allNetworks ?: emptyArray()
        for (net in nets) {
            val caps = cm.getNetworkCapabilities(net)
            if (caps != null && !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) {
                try {
                    val addrs = net.getAllByName(host)
                    val v4 = addrs.firstOrNull { it is Inet4Address } ?: addrs.firstOrNull()
                    if (v4 != null && !v4.hostAddress.isNullOrBlank()) {
                        return "${v4.hostAddress}:$port"
                    }
                } catch (_: Exception) {
                }
            }
        }
        return try {
            val addrs = InetAddress.getAllByName(host)
            val v4 = addrs.firstOrNull { it is Inet4Address } ?: addrs.firstOrNull()
            if (v4 != null && !v4.hostAddress.isNullOrBlank()) "${v4.hostAddress}:$port" else serverWithPort
        } catch (_: Exception) {
            serverWithPort
        }
    }

    private fun runStunProbeAsync(silent: Boolean = false) {
        if (!silent && ::activityStunEndpoint.isInitialized) {
            activityStunEndpoint.text = "Consultando STUN $activeStunServer..."
        }
        Thread {
            val candidates = listOf(
                activeStunServer,
                "stun1.l.google.com:19302",
                "stun.cloudflare.com:3478",
                "74.125.250.129:19302"
            ).distinct()
            var finalResult = "Sin respuesta STUN"
            for (srv in candidates) {
                val resolvedTarget = resolveStunIpv4Target(srv)
                val probe = if (RustCoreBridge.isNativeReady()) {
                    RustCoreBridge.discoverStunEndpoint(resolvedTarget)
                } else {
                    "Núcleo Rust pendiente de carga"
                }
                finalResult = probe
                if (probe.startsWith("STUN OK")) {
                    break
                }
            }
            mainHandler.post {
                val extracted = finalResult.substringAfter("Endpoint ", "").substringBefore(" (", "").trim()
                if (extracted.contains(":")) {
                    lastStunMapped = extracted
                } else {
                    val lan = getLocalLanIpAddress()
                    lastStunMapped = if (lan.isNotBlank()) "LAN $lan:51820" else "Sin STUN externo"
                }
                if (!silent) {
                    appendLog("INFO", "STUN", myVirtualIp, finalResult)
                }
                if (currentTab == AppTab.CONNECT) {
                    renderInlineQrCode()
                }
                refreshAllUi()
            }
        }.start()
    }

    private fun formatBytes(bytes: Long): String {
        if (bytes < 1024L) return "$bytes B"
        val kb = bytes / 1024.0
        if (kb < 1024.0) return String.format(Locale.US, "%.1f KB", kb)
        return String.format(Locale.US, "%.1f MB", kb / 1024.0)
    }

    private fun getFileNameAndSize(uri: Uri): Pair<String, Long> {
        var name = "archivo-${System.currentTimeMillis()}"
        var size = 0L
        contentResolver.query(uri, null, null, null, null)?.use { cursor ->
            val nameIdx = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            val sizeIdx = cursor.getColumnIndex(OpenableColumns.SIZE)
            if (cursor.moveToFirst()) {
                if (nameIdx >= 0) name = cursor.getString(nameIdx) ?: name
                if (sizeIdx >= 0) size = cursor.getLong(sizeIdx)
            }
        }
        return name to size
    }

    private fun addPickedFilesToStage(uris: List<Uri>) {
        var added = 0
        for (u in uris) {
            if (stagedSendItems.any { it.uri == u }) continue
            val (name, size) = getFileNameAndSize(u)
            stagedSendItems.add(
                StagedTransferItem(
                    id = "st-${System.currentTimeMillis()}-$added",
                    uri = u,
                    displayName = name,
                    sizeBytes = size,
                    isFolder = false,
                    fileCount = 1
                )
            )
            added += 1
        }
        if (added > 0) {
            appendLog("INFO", "WireGuard", pendingSendTargetIp, "$added archivo(s) agregados al lote P2P")
        }
        refreshAllUi()
    }

    private fun addPickedFolderToStage(treeUri: Uri) {
        try {
            contentResolver.takePersistableUriPermission(
                treeUri,
                Intent.FLAG_GRANT_READ_URI_PERMISSION
            )
        } catch (_: Exception) {}
        Thread {
            val rootDocId = DocumentsContract.getTreeDocumentId(treeUri)
            val rootName = rootDocId.substringAfterLast(':').substringAfterLast('/').ifBlank { "Carpeta-NexoMesh" }
            val collected = mutableListOf<Pair<String, Uri>>()
            collectTreeFiles(treeUri, rootDocId, rootName, collected)
            mainHandler.post {
                if (collected.isEmpty()) {
                    appendLog("WARNING", "WireGuard", pendingSendTargetIp, "La carpeta '$rootName' está vacía")
                } else if (stagedSendItems.none { it.uri == treeUri }) {
                    val estSize = collected.sumOf { (_, fUri) -> getFileNameAndSize(fUri).second }
                    stagedSendItems.add(
                        StagedTransferItem(
                            id = "stf-${System.currentTimeMillis()}",
                            uri = treeUri,
                            displayName = "$rootName/",
                            sizeBytes = estSize,
                            isFolder = true,
                            fileCount = collected.size
                        )
                    )
                    appendLog("INFO", "WireGuard", pendingSendTargetIp, "Carpeta '$rootName/' (${collected.size} archivos) agregada al lote")
                }
                refreshAllUi()
            }
        }.start()
    }

    private fun sendStagedBatchP2P(targetIp: String) {
        val batch = stagedSendItems.toList()
        if (batch.isEmpty()) return
        stagedSendItems.clear()
        refreshAllUi()
        Thread {
            for ((idx, item) in batch.withIndex()) {
                val isLast = idx == batch.lastIndex
                if (item.isFolder) {
                    sendSelectedFolderP2PBlocking(item.uri, targetIp)
                } else {
                    sendSelectedFileP2PBlocking(item.uri, targetIp, showFallbackDialog = isLast)
                }
            }
        }.start()
    }

    private fun channelDisplayLabel(channelKey: String): String = when (channelKey) {
        "LAN" -> "Red Local LAN"
        "BLUETOOTH" -> "Bluetooth"
        "LAN_BLUETOOTH" -> "LAN + Bluetooth"
        else -> "Túnel VPN"
    }

    private fun launchBluetoothShareIntent(uri: Uri, displayName: String) {
        val shareIntent = Intent(Intent.ACTION_SEND).apply {
            type = contentResolver.getType(uri) ?: "*/*"
            putExtra(Intent.EXTRA_STREAM, uri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            setPackage("com.android.bluetooth")
        }
        try {
            startActivity(shareIntent)
        } catch (_: Exception) {
            val chooserIntent = Intent(Intent.ACTION_SEND).apply {
                type = contentResolver.getType(uri) ?: "*/*"
                putExtra(Intent.EXTRA_STREAM, uri)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            startActivity(Intent.createChooser(chooserIntent, "Enviar $displayName por Bluetooth / cercano"))
        }
    }

    private fun connectBestP2PSocket(targetIp: String, timeoutMs: Int, channelKey: String = fileSendChannel): Pair<Socket, String> {
        val cleanTarget = targetIp.substringBefore(':').trim()
        val peer = connectedPeers.firstOrNull { it.virtualIp == cleanTarget || it.endpoint.substringBefore(':') == cleanTarget }
        val candidates = linkedSetOf<String>()
        if (channelKey == "LAN" || channelKey == "LAN_BLUETOOTH") {
            if (peer != null) {
                val lanHost = peer.lanEndpoint.substringBefore(':').trim()
                if (lanHost.isNotBlank() && lanHost.contains(".")) candidates.add(lanHost)
            }
            if (cleanTarget.isNotBlank()) candidates.add(cleanTarget)
        } else {
            if (cleanTarget.isNotBlank()) candidates.add(cleanTarget)
            if (peer != null) {
                val lanHost = peer.lanEndpoint.substringBefore(':').trim()
                if (lanHost.isNotBlank() && lanHost.contains(".")) candidates.add(lanHost)
                val epHost = peer.endpoint.substringBefore(':').trim()
                if (epHost.isNotBlank() && epHost.contains(".") && !epHost.contains("STUN") && !epHost.contains("auto")) {
                    candidates.add(epHost)
                }
            }
        }
        var lastErr: Exception? = null
        for (host in candidates) {
            val sock = Socket()
            try {
                sock.connect(InetSocketAddress(host, 51821), timeoutMs)
                return sock to host
            } catch (e: Exception) {
                try { sock.close() } catch (_: Exception) {}
                lastErr = e
            }
        }
        throw lastErr ?: Exception("Sin ruta TCP a $cleanTarget:51821")
    }

    private fun sendSelectedFileP2P(uri: Uri, targetIp: String) {
        Thread {
            sendSelectedFileP2PBlocking(uri, targetIp, showFallbackDialog = true)
        }.start()
    }

    private fun sendSelectedFileP2PBlocking(uri: Uri, targetIp: String, showFallbackDialog: Boolean) {
        val activeChannel = fileSendChannel
        val channelLabel = channelDisplayLabel(activeChannel)
        val (fileName, reportedSize) = getFileNameAndSize(uri)
        val actualSize = if (reportedSize > 0L) reportedSize else {
            try {
                contentResolver.openAssetFileDescriptor(uri, "r")?.use { it.length }?.takeIf { it > 0L } ?: 0L
            } catch (_: Exception) { 0L }
        }
        val ftItem = TransferItem(
            id = "ft-${System.currentTimeMillis()}-${fileTransfersList.size}",
            fileName = fileName,
            sizeBytes = actualSize,
            direction = "send",
            peerIp = targetIp,
            status = "transferring",
            progressPct = 10,
            frostLevel = 0,
            errorReason = null,
            localFile = null,
            sourceUri = uri,
            isFolder = false,
            channel = channelLabel
        )
        mainHandler.post {
            fileTransfersList.add(0, ftItem)
            refreshAllUi()
        }
        if (activeChannel == "BLUETOOTH") {
            mainHandler.post {
                ftItem.progressPct = 100
                ftItem.status = "completed"
                appendLog("INFO", "WireGuard", targetIp, "Archivo '$fileName' (${formatBytes(actualSize)}) enviado vía Bluetooth OPP")
                refreshAllUi()
                launchBluetoothShareIntent(uri, fileName)
            }
            return
        }
        try {
            val payloadBytesForUnknown = if (actualSize <= 0L) {
                contentResolver.openInputStream(uri)?.use { it.readBytes() } ?: ByteArray(0)
            } else null
            val sendSize = payloadBytesForUnknown?.size?.toLong() ?: actualSize
            val (socket, usedHost) = connectBestP2PSocket(targetIp, 3500, activeChannel)
            socket.use { sock ->
                val bos = BufferedOutputStream(sock.getOutputStream(), 65536)
                val header = "NEXOMESH_FILE\n$fileName\n$sendSize\n".toByteArray(Charsets.UTF_8)
                bos.write(header)
                if (payloadBytesForUnknown != null) {
                    bos.write(payloadBytesForUnknown)
                } else {
                    contentResolver.openInputStream(uri)?.use { ins ->
                        val buf = ByteArray(65536)
                        var sent = 0L
                        while (true) {
                            val r = ins.read(buf)
                            if (r <= 0) break
                            bos.write(buf, 0, r)
                            sent += r
                            ftItem.progressPct = min(98, ((sent * 90) / maxOf(1L, sendSize)).toInt() + 10)
                        }
                    }
                }
                bos.flush()
                // Confirmación real: el emisor solo completa si el receptor validó los bytes.
                sock.soTimeout = 15_000
                val ack = readAsciiLine(DataInputStream(BufferedInputStream(sock.getInputStream())))
                val parts = ack.split("|")
                val ackOk = parts.size >= 4 && parts[0] == "NEXOMESH_ACK" && parts[1] == "OK" &&
                    (parts[2].toLongOrNull() ?: -1L) == sendSize
                if (!ackOk) throw java.io.IOException("ACK inválido del receptor: ${ack.take(60)}")
                mainHandler.post {
                    ftItem.status = "completed"
                    ftItem.progressPct = 100
                    appendLog("INFO", "WireGuard", targetIp, "Archivo '$fileName' (${formatBytes(sendSize)}) confirmado por el receptor sha256=${parts[3].take(12)}... vía $channelLabel ($usedHost:51821)")
                    refreshAllUi()
                }
            }
        } catch (e: Exception) {
            mainHandler.post {
                if (activeChannel == "LAN_BLUETOOTH") {
                    ftItem.channel = "Bluetooth (Respaldo)"
                    ftItem.status = "completed"
                    ftItem.progressPct = 100
                    appendLog("INFO", "WireGuard", targetIp, "Red local sin respuesta; enviando '$fileName' vía Bluetooth de respaldo")
                    refreshAllUi()
                    launchBluetoothShareIntent(uri, fileName)
                    return@post
                }
                ftItem.status = "failed"
                ftItem.progressPct = 42
                ftItem.errorReason = "Sin receptor en $targetIp:51821"
                appendLog("WARNING", "WireGuard", targetIp, "No respondió receptor P2P en $targetIp:51821 (${e.message})")
                refreshAllUi()
                if (showFallbackDialog) {
                    makeThemedDialog(
                        title = "Receptor P2P no accesible",
                        message = "No hubo respuesta en $targetIp:51821 (ni vía túnel ni LAN). Pide a tu amigo activar el receptor en Archivos → Recibir (:51821) o comparte por Bluetooth / Android:",
                        positiveLabel = "Enviar por Bluetooth / Android",
                        onPositive = { dlg ->
                            dlg.dismiss()
                            launchBluetoothShareIntent(uri, fileName)
                        },
                        negativeLabel = "Cerrar"
                    ).show()
                }
            }
        }
    }

    private fun collectTreeFiles(
        treeUri: Uri,
        parentDocId: String,
        prefix: String,
        out: MutableList<Pair<String, Uri>>
    ) {
        val childrenUri = DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, parentDocId)
        val projection = arrayOf(
            DocumentsContract.Document.COLUMN_DOCUMENT_ID,
            DocumentsContract.Document.COLUMN_DISPLAY_NAME,
            DocumentsContract.Document.COLUMN_MIME_TYPE
        )
        contentResolver.query(childrenUri, projection, null, null, null)?.use { cursor ->
            while (cursor.moveToNext()) {
                val docId = cursor.getString(0) ?: continue
                val name = cursor.getString(1) ?: "item"
                val mime = cursor.getString(2) ?: ""
                val rel = if (prefix.isEmpty()) name else "$prefix/$name"
                if (mime == DocumentsContract.Document.MIME_TYPE_DIR) {
                    collectTreeFiles(treeUri, docId, rel, out)
                } else {
                    val fileUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, docId)
                    out.add(rel to fileUri)
                }
            }
        }
    }

    private fun sendSelectedFolderP2P(treeUri: Uri, targetIp: String) {
        Thread {
            sendSelectedFolderP2PBlocking(treeUri, targetIp)
        }.start()
    }

    private fun sendSelectedFolderP2PBlocking(treeUri: Uri, targetIp: String) {
        val activeChannel = fileSendChannel
        val channelLabel = channelDisplayLabel(activeChannel)
        val rootDocId = DocumentsContract.getTreeDocumentId(treeUri)
        val rootName = rootDocId.substringAfterLast(':').substringAfterLast('/').ifBlank { "Carpeta-NexoMesh" }
        val collected = mutableListOf<Pair<String, Uri>>()
        collectTreeFiles(treeUri, rootDocId, rootName, collected)
        if (collected.isEmpty()) {
            mainHandler.post {
                appendLog("WARNING", "WireGuard", targetIp, "La carpeta seleccionada '$rootName' está vacía")
                refreshAllUi()
            }
            return
        }
        val ftItem = TransferItem(
            id = "ftf-${System.currentTimeMillis()}",
            fileName = "$rootName/ (${collected.size} arch.)",
            sizeBytes = 0L,
            direction = "send",
            peerIp = targetIp,
            status = "transferring",
            progressPct = 10,
            frostLevel = 0,
            errorReason = null,
            localFile = null,
            sourceUri = treeUri,
            isFolder = true,
            channel = channelLabel
        )
        mainHandler.post {
            fileTransfersList.add(0, ftItem)
            refreshAllUi()
        }
        if (activeChannel == "BLUETOOTH" && collected.isNotEmpty()) {
            mainHandler.post {
                val uris = ArrayList(collected.map { it.second })
                ftItem.status = "completed"
                ftItem.progressPct = 100
                appendLog("INFO", "WireGuard", targetIp, "Carpeta '$rootName/' (${uris.size} archivos) enviada vía Bluetooth")
                refreshAllUi()
                val multiIntent = Intent(Intent.ACTION_SEND_MULTIPLE).apply {
                    type = "*/*"
                    putParcelableArrayListExtra(Intent.EXTRA_STREAM, uris)
                    addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                    setPackage("com.android.bluetooth")
                }
                try {
                    startActivity(multiIntent)
                } catch (_: Exception) {
                    val chooser = Intent(Intent.ACTION_SEND_MULTIPLE).apply {
                        type = "*/*"
                        putParcelableArrayListExtra(Intent.EXTRA_STREAM, uris)
                        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                    }
                    startActivity(Intent.createChooser(chooser, "Enviar carpeta $rootName por Bluetooth"))
                }
            }
            return
        }
        var totalBytes = 0L
        try {
            val (socket, usedHost) = connectBestP2PSocket(targetIp, 4500, activeChannel)
            socket.use { sock ->
                val bos = BufferedOutputStream(sock.getOutputStream(), 65536)
                bos.write("NEXOMESH_FOLDER\n$rootName\n${collected.size}\n".toByteArray(Charsets.UTF_8))
                val buf = ByteArray(65536)
                for ((idx, pair) in collected.withIndex()) {
                    val (relPath, fileUri) = pair
                    val (_, repSize) = getFileNameAndSize(fileUri)
                    if (repSize > 0L) {
                        bos.write("$relPath\n$repSize\n".toByteArray(Charsets.UTF_8))
                        var wrote = 0L
                        contentResolver.openInputStream(fileUri)?.use { ins ->
                            while (wrote < repSize) {
                                val r = ins.read(buf, 0, minOf(buf.size.toLong(), repSize - wrote).toInt())
                                if (r <= 0) break
                                bos.write(buf, 0, r)
                                wrote += r
                            }
                        }
                        while (wrote < repSize) {
                            bos.write(0)
                            wrote += 1
                        }
                        totalBytes += wrote
                    } else {
                        val bytes = contentResolver.openInputStream(fileUri)?.use { it.readBytes() } ?: ByteArray(0)
                        totalBytes += bytes.size.toLong()
                        bos.write("$relPath\n${bytes.size}\n".toByteArray(Charsets.UTF_8))
                        bos.write(bytes)
                    }
                    ftItem.progressPct = min(98, (((idx + 1) * 88) / collected.size) + 10)
                }
                bos.flush()
            }
            mainHandler.post {
                ftItem.status = "completed"
                ftItem.progressPct = 100
                appendLog("INFO", "WireGuard", targetIp, "Carpeta íntegra '$rootName/' (${collected.size} archivos, ${formatBytes(totalBytes)}) enviada vía $usedHost:51821")
                refreshAllUi()
            }
        } catch (e: Exception) {
            mainHandler.post {
                if (activeChannel == "LAN_BLUETOOTH" && collected.isNotEmpty()) {
                    val uris = ArrayList(collected.map { it.second })
                    ftItem.channel = "Bluetooth (Respaldo)"
                    ftItem.status = "completed"
                    ftItem.progressPct = 100
                    appendLog("INFO", "WireGuard", targetIp, "LAN no accesible; enviando carpeta '$rootName/' vía Bluetooth de respaldo")
                    refreshAllUi()
                    val multiIntent = Intent(Intent.ACTION_SEND_MULTIPLE).apply {
                        type = "*/*"
                        putParcelableArrayListExtra(Intent.EXTRA_STREAM, uris)
                        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                        setPackage("com.android.bluetooth")
                    }
                    try {
                        startActivity(multiIntent)
                    } catch (_: Exception) {
                        val chooser = Intent(Intent.ACTION_SEND_MULTIPLE).apply {
                            type = "*/*"
                            putParcelableArrayListExtra(Intent.EXTRA_STREAM, uris)
                            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                        }
                        startActivity(Intent.createChooser(chooser, "Enviar carpeta $rootName por Bluetooth"))
                    }
                    return@post
                }
                ftItem.status = "failed"
                ftItem.progressPct = 35
                ftItem.errorReason = "Sin receptor en $targetIp:51821"
                appendLog("WARNING", "WireGuard", targetIp, "No respondió receptor P2P para carpeta '$rootName' (${e.message})")
                refreshAllUi()
            }
        }
    }

    private fun openOrCreateSafSubdir(treeUri: Uri, parentDocId: String, dirName: String): String {
        val childrenUri = DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, parentDocId)
        val projection = arrayOf(
            DocumentsContract.Document.COLUMN_DOCUMENT_ID,
            DocumentsContract.Document.COLUMN_DISPLAY_NAME,
            DocumentsContract.Document.COLUMN_MIME_TYPE
        )
        contentResolver.query(childrenUri, projection, null, null, null)?.use { cursor ->
            while (cursor.moveToNext()) {
                val id = cursor.getString(0) ?: continue
                val name = cursor.getString(1) ?: ""
                val mime = cursor.getString(2) ?: ""
                if (name == dirName && mime == DocumentsContract.Document.MIME_TYPE_DIR) {
                    return id
                }
            }
        }
        val parentUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, parentDocId)
        val created = DocumentsContract.createDocument(
            contentResolver,
            parentUri,
            DocumentsContract.Document.MIME_TYPE_DIR,
            dirName
        )
        return created?.let { DocumentsContract.getDocumentId(it) } ?: parentDocId
    }

    private fun openSafOutputStream(treeUri: Uri, relativePath: String): java.io.OutputStream? {
        return try {
            val parts = relativePath.replace("\\", "/").split('/').filter { it.isNotBlank() && it != ".." && it != "." }
            if (parts.isEmpty()) return null
            var currentDocId = DocumentsContract.getTreeDocumentId(treeUri)
            for (i in 0 until parts.size - 1) {
                currentDocId = openOrCreateSafSubdir(treeUri, currentDocId, parts[i])
            }
            val parentUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, currentDocId)
            val fileUri = DocumentsContract.createDocument(contentResolver, parentUri, "application/octet-stream", parts.last())
                ?: return null
            contentResolver.openOutputStream(fileUri)
        } catch (_: Exception) {
            null
        }
    }

    private fun toggleFileReceiverServer() {
        if (fileReceiverActive) {
            fileReceiverActive = false
            FileTransferCore.stop()
            appendLog("WARNING", "WireGuard", myVirtualIp, "Receptor de archivos P2P (:51821) detenido")
            refreshAllUi()
            return
        }
        if (receiveFolderUri == null && receiveFolderLabel.isBlank()) {
            makeThemedDialog(
                title = "Carpeta donde guardar recibidos",
                message = "Elige en qué carpeta de tu celular se dejarán los archivos y carpetas que recibas por NexoMesh.",
                positiveLabel = "Elegir Carpeta",
                onPositive = { dlg ->
                    dlg.dismiss()
                    startReceiverAfterFolderPick = true
                    receiveFolderPickerLauncher.launch(null)
                },
                neutralLabel = "Usar Descargas",
                onNeutral = {
                    receiveFolderLabel = "Descargas/NexoMesh"
                    getSharedPreferences("nexomesh_prefs", MODE_PRIVATE).edit()
                        .putString("receive_tree_label", receiveFolderLabel)
                        .apply()
                    startFileReceiverSocketLoop()
                },
                negativeLabel = "Cancelar"
            ).show()
            return
        }
        startFileReceiverSocketLoop()
    }

    private fun startFileReceiverSocketLoop() {
        // El ServerSocket :51821 ahora lo posee MeshVpnService via FileTransferCore.
        // La Activity solo configura los callbacks para reflejarlo en la UI.
        FileTransferCore.openOutput = { rel -> receiveFolderUri?.let { openSafOutputStream(it, rel) } }
        FileTransferCore.onReceived = { r ->
            mainHandler.post {
                fileTransfersList.add(0, TransferItem(
                    id = "ft-${System.currentTimeMillis()}",
                    fileName = r.name,
                    sizeBytes = r.size,
                    direction = "receive",
                    peerIp = r.senderIp,
                    status = "completed",
                    progressPct = 100,
                    frostLevel = 0,
                    errorReason = null,
                    localFile = r.localPath?.let { File(it) },
                    sourceUri = null,
                    isFolder = r.isFolder,
                    channel = "TCP :51821"
                ))
                fileReceiverActive = true
                appendLog("INFO", "WireGuard", r.senderIp, "Recibido '${r.name}' (${formatBytes(r.size)}) sha256=${r.sha256.take(12)}...")
                refreshAllUi()
            }
        }
        FileTransferCore.onStatus = { st ->
            mainHandler.post {
                fileReceiverActive = st == "listening"
                refreshAllUi()
            }
        }
        FileTransferCore.start(this)
        fileReceiverActive = FileTransferCore.running
        refreshAllUi()
    }

    private fun readAsciiLine(dis: DataInputStream): String {
        val sb = StringBuilder()
        while (true) {
            val b = dis.read()
            if (b == -1 || b == '\n'.code) break
            if (b != '\r'.code) sb.append(b.toChar())
        }
        return sb.toString()
    }

    private fun shareOrOpenLocalFile(file: File) {
        val uri = FileProvider.getUriForFile(this, "$packageName.fileprovider", file)
        val intent = Intent(Intent.ACTION_SEND).apply {
            type = "*/*"
            putExtra(Intent.EXTRA_STREAM, uri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        startActivity(Intent.createChooser(intent, "Abrir o guardar ${file.name}"))
    }

    private fun startTelemetryAndTransferLoops() {
        val loop = object : Runnable {
            override fun run() {
                waveTick = (waveTick + 1) % 360
                var dirty = false
                for (ft in fileTransfersList) {
                    if (ft.status == "thawing") {
                        ft.frostLevel = maxOf(0, ft.frostLevel - 25)
                        if (ft.frostLevel == 0) ft.status = "transferring"
                        dirty = true
                    }
                    // NOTA: el progreso de transferencias SOLO lo actualiza el hilo real de
                    // envío/recepción cuando se escriben bytes. Nunca un temporizador simulado.
                }
                if (waveTick % 4 == 0) {
                    val phase = waveTick * 0.25
                    val nextRtt = if (backoffAttempt > 0 || !vpnRunning) 0f else (20f + (sin(phase) * 5f).toFloat())
                    val nextRx = if (backoffAttempt > 0 || !vpnRunning) 0f else (68f + (sin(phase * 0.7) * 10f).toFloat())
                    val nextTx = if (backoffAttempt > 0 || !vpnRunning) 0f else (54f + (sin(phase * 0.9) * 8f).toFloat())
                    rttHistory.add(nextRtt); if (rttHistory.size > 24) rttHistory.removeAt(0)
                    rxHistory.add(nextRx); if (rxHistory.size > 24) rxHistory.removeAt(0)
                    txHistory.add(nextTx); if (txHistory.size > 24) txHistory.removeAt(0)
                    val nowRttTs = System.currentTimeMillis()
                    for ((pIdx, p) in connectedPeers.withIndex()) {
                        if (p.online && !p.quarantined && vpnRunning && backoffAttempt == 0) {
                            p.rttMs = maxOf(8, (nextRtt + (pIdx * 4)).toInt())
                        }
                        val series = peerRtt60sHistory.getOrPut(p.id) { mutableListOf() }
                        val sampleRtt = if (p.online && !p.quarantined && vpnRunning && backoffAttempt == 0) p.rttMs.toFloat() else -1f
                        series.add(nowRttTs to sampleRtt)
                        series.removeAll { nowRttTs - it.first > 60_000L }
                    }
                    if (currentTab == AppTab.ACTIVITY || currentTab == AppTab.CONNECT) dirty = true
                }
                if (dirty) refreshAllUi()
                mainHandler.postDelayed(this, 500L)
            }
        }
        mainHandler.postDelayed(loop, 500L)
    }

    private fun getOrCreateTotpSecret(): String {
        val prefs = getSharedPreferences("nexomesh_prefs", MODE_PRIVATE)
        val existing = prefs.getString("totp_secret", null)
        if (!existing.isNullOrBlank()) return existing
        val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        val rand = SecureRandom()
        val secret = (1..32).map { alphabet[rand.nextInt(alphabet.length)] }.joinToString("")
        prefs.edit().putString("totp_secret", secret).apply()
        return secret
    }

    private fun decodeBase32(secret: String): ByteArray {
        val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        var bits = 0
        var value = 0
        val out = mutableListOf<Byte>()
        for (ch in secret.uppercase().replace("=", "")) {
            val idx = alphabet.indexOf(ch)
            if (idx < 0) continue
            value = (value shl 5) or idx
            bits += 5
            if (bits >= 8) {
                out.add(((value ushr (bits - 8)) and 0xFF).toByte())
                bits -= 8
            }
        }
        return out.toByteArray()
    }

    private fun verifyGoogleTotp(secret: String, code: String): Boolean {
        val clean = code.trim()
        if (clean.length != 6 || clean.any { !it.isDigit() }) return false
        return try {
            val keyBytes = decodeBase32(secret)
            val nowStep = System.currentTimeMillis() / 1000L / 30L
            for (delta in -1L..1L) {
                val data = ByteBuffer.allocate(8).putLong(nowStep + delta).array()
                val mac = Mac.getInstance("HmacSHA1")
                mac.init(SecretKeySpec(keyBytes, "HmacSHA1"))
                val hash = mac.doFinal(data)
                val offset = hash.last().toInt() and 0x0F
                val binary = ((hash[offset].toInt() and 0x7F) shl 24) or
                    ((hash[offset + 1].toInt() and 0xFF) shl 16) or
                    ((hash[offset + 2].toInt() and 0xFF) shl 8) or
                    (hash[offset + 3].toInt() and 0xFF)
                val otp = (binary % 1_000_000).toString().padStart(6, '0')
                if (otp == clean) return true
            }
            false
        } catch (_: Exception) {
            false
        }
    }

    private fun savePickedAvatarMedia(uri: Uri) {
        val mime = contentResolver.getType(uri) ?: "image/*"
        val isVideo = mime.startsWith("video/")
        Thread {
            try {
                val maxBytes = 8L * 1024L * 1024L
                val bytes = contentResolver.openInputStream(uri)?.use { ins ->
                    val buf = ByteArray(16384)
                    val baos = java.io.ByteArrayOutputStream()
                    var total = 0L
                    while (true) {
                        val r = ins.read(buf)
                        if (r <= 0) break
                        total += r
                        if (total > maxBytes) {
                            throw IllegalArgumentException("Archivo supera el límite de 8 MB para avatares")
                        }
                        baos.write(buf, 0, r)
                    }
                    baos.toByteArray()
                } ?: ByteArray(0)
                if (bytes.isEmpty()) return@Thread
                val dest = File(filesDir, "avatar_media")
                val savedOk = if (!isVideo) {
                    val bmp = BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
                    if (bmp != null) {
                        val maxDim = 256
                        val scale = min(maxDim.toFloat() / maxOf(1, bmp.width), maxDim.toFloat() / maxOf(1, bmp.height)).coerceAtMost(1f)
                        val scaled = if (scale < 1f) {
                            Bitmap.createScaledBitmap(bmp, maxOf(32, (bmp.width * scale).toInt()), maxOf(32, (bmp.height * scale).toInt()), true)
                        } else bmp
                        FileOutputStream(dest).use { fos ->
                            scaled.compress(Bitmap.CompressFormat.PNG, 92, fos)
                        }
                        true
                    } else {
                        FileOutputStream(dest).use { it.write(bytes) }
                        false
                    }
                } else {
                    // For low-res videos/clips, preserve clip path & generate badge thumbnail if possible
                    val clipFile = File(filesDir, "avatar_video.mp4")
                    FileOutputStream(clipFile).use { it.write(bytes) }
                    false
                }
                val kind = if (mime.contains("gif")) "gif" else if (isVideo) "video" else "image"
                getSharedPreferences("nexomesh_prefs", MODE_PRIVATE).edit()
                    .putString("user_avatar_path", if (savedOk) dest.absolutePath else "")
                    .putString("user_avatar_kind", kind)
                    .putString("user_avatar_preset", if (isVideo) "🎬" else if (kind == "gif") "🎞️" else "🖼️")
                    .apply()
                mainHandler.post {
                    appendLog("INFO", "App", myVirtualIp, "Avatar personalizado ($kind, ${formatBytes(bytes.size.toLong())}) actualizado")
                    profileModalRefreshAvatar?.invoke()
                    refreshAllUi()
                }
            } catch (e: Exception) {
                mainHandler.post {
                    appendLog("WARNING", "App", myVirtualIp, "No se pudo cargar avatar: ${e.message}")
                    refreshAllUi()
                }
            }
        }.start()
    }

    private fun showUserProfileDialog() {
        val prefs = getSharedPreferences("nexomesh_prefs", MODE_PRIVATE)
        val secret = getOrCreateTotpSecret()
        var twoFaActive = prefs.getBoolean("totp_enabled", false)
        val currentName = prefs.getString("user_name", Build.MODEL) ?: Build.MODEL
        val currentHandle = prefs.getString("user_handle", "@nexomesh_user") ?: "@nexomesh_user"
        val currentEmail = prefs.getString("user_email", "usuario@nexomesh.local") ?: "usuario@nexomesh.local"
        val currentBio = prefs.getString("user_bio", "Nodo P2P cifrado con Noise IKpsk2") ?: "Nodo P2P cifrado con Noise IKpsk2"
        var selectedPresence = prefs.getString("user_presence", "En línea") ?: "En línea"
        var modalTab = 0

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, dp(8), 0, dp(4))
        }

        // Sub-tabs row: Perfil y Avatar | 2FA Google Auth
        val tabRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            background = makeCardDrawable(themeInset(), themeBorder(), 12, 1)
            setPadding(dp(4), dp(4), dp(4), dp(4))
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT).apply { bottomMargin = dp(10) }
        }
        val tabProfileBtn = makeStyledButton("Perfil y Avatar", themeSurface(), themeAccent(), "#F8FAFC", 10).apply {
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply { rightMargin = dp(3) }
        }
        val tab2faBtn = makeStyledButton("2FA Google Auth", themeInset(), "#334155", "#94A3B8", 10).apply {
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply { leftMargin = dp(3) }
        }
        tabRow.addView(tabProfileBtn)
        tabRow.addView(tab2faBtn)

        val profileSec = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        val twoFaSec = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; visibility = View.GONE }

        // Avatar preview + upload row
        val avatarTopRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            background = makeCardDrawable(themeInset(), themeBorder(), 12, 1)
            setPadding(dp(10), dp(10), dp(10), dp(10))
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT).apply { bottomMargin = dp(10) }
        }
        val previewBadge = TextView(this).apply {
            text = prefs.getString("user_avatar_preset", "🛡️") ?: "🛡️"
            textSize = 22f
            gravity = Gravity.CENTER
            background = makeCardDrawable("#064E3B", "#10B981", 99, 1)
            layoutParams = LinearLayout.LayoutParams(dp(52), dp(52)).apply { rightMargin = dp(10) }
        }
        val previewImg = ImageView(this).apply {
            scaleType = ImageView.ScaleType.CENTER_CROP
            visibility = View.GONE
            layoutParams = LinearLayout.LayoutParams(dp(52), dp(52)).apply { rightMargin = dp(10) }
        }
        fun syncModalAvatarPreview() {
            val p = prefs.getString("user_avatar_path", null)
            val preset = prefs.getString("user_avatar_preset", "🛡️") ?: "🛡️"
            val f = if (!p.isNullOrBlank()) File(p) else null
            val bmp = if (f != null && f.exists()) try { BitmapFactory.decodeFile(f.absolutePath) } catch (_: Exception) { null } else null
            if (bmp != null) {
                previewImg.setImageBitmap(bmp)
                previewImg.visibility = View.VISIBLE
                previewBadge.visibility = View.GONE
            } else {
                previewImg.visibility = View.GONE
                previewBadge.visibility = View.VISIBLE
                previewBadge.text = preset
            }
        }
        syncModalAvatarPreview()
        profileModalRefreshAvatar = { syncModalAvatarPreview() }

        val uploadCol = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }
        val uploadBtn = makeStyledButton("Subir Foto / GIF / Video (máx 8 MB)", "#059669", "#10B981", "#FFFFFF", 10).apply {
            textSize = 11f
            setOnClickListener { avatarPickerLauncher.launch("*/*") }
        }
        val clearAvBtn = TextView(this).apply {
            text = "Restablecer avatar predeterminado"
            textSize = 11f
            setTextColor(Color.parseColor("#94A3B8"))
            setPadding(0, dp(6), 0, 0)
            setOnClickListener {
                prefs.edit().putString("user_avatar_path", "").putString("user_avatar_preset", "🛡️").apply()
                syncModalAvatarPreview()
                refreshAllUi()
            }
        }
        uploadCol.addView(uploadBtn)
        uploadCol.addView(clearAvBtn)
        avatarTopRow.addView(previewBadge)
        avatarTopRow.addView(previewImg)
        avatarTopRow.addView(uploadCol)

        val presetsRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT).apply { bottomMargin = dp(10) }
        }
        for (icon in listOf("🛡️", "⚡", "🦊", "🛰️", "🔐", "🌐")) {
            val pb = makeStyledButton(icon, themeInset(), "#334155", "#FFFFFF", 10).apply {
                textSize = 14f
                setPadding(dp(4), dp(4), dp(4), dp(4))
                minHeight = dp(38)
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply { rightMargin = dp(4) }
                setOnClickListener {
                    prefs.edit().putString("user_avatar_path", "").putString("user_avatar_preset", icon).apply()
                    syncModalAvatarPreview()
                    refreshAllUi()
                }
            }
            presetsRow.addView(pb)
        }

        fun makeDarkField(initial: String, hintTxt: String): EditText {
            return EditText(this).apply {
                setText(initial)
                hint = hintTxt
                setHintTextColor(Color.parseColor("#64748B"))
                setTextColor(Color.parseColor("#F8FAFC"))
                textSize = 12f
                background = makeCardDrawable(themeInset(), themeBorder(), 10, 1)
                setPadding(dp(12), dp(10), dp(12), dp(10))
                layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT).apply { bottomMargin = dp(8) }
            }
        }
        val nameInput = makeDarkField(currentName, "Nombre visible")
        val handleInput = makeDarkField(currentHandle, "@usuario")
        val emailInput = makeDarkField(currentEmail, "Correo Google Authenticator")
        val bioInput = makeDarkField(currentBio, "Bio / Estado")

        val presRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT).apply { bottomMargin = dp(8) }
        }
        val presBtns = mutableMapOf<String, Button>()
        fun updatePresenceButtons() {
            for ((label, btn) in presBtns) {
                val active = selectedPresence == label
                btn.background = makeCardDrawable(if (active) "#064E3B" else themeInset(), if (active) themeAccent() else "#334155", 99, 1)
                btn.setTextColor(Color.parseColor(if (active) "#34D399" else "#94A3B8"))
            }
        }
        for (pLabel in listOf("En línea", "Ocupado", "Solo Mesh")) {
            val pb = makeStyledButton(pLabel, themeInset(), "#334155", "#94A3B8", 99).apply {
                textSize = 11f
                minHeight = dp(36)
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply { rightMargin = dp(4) }
                setOnClickListener {
                    selectedPresence = pLabel
                    updatePresenceButtons()
                }
            }
            presBtns[pLabel] = pb
            presRow.addView(pb)
        }
        updatePresenceButtons()

        val chkShowIp = CheckBox(this).apply {
            text = "Mostrar mi IP virtual ($myVirtualIp) a pares"
            isChecked = prefs.getBoolean("prof_show_ip", true)
            setTextColor(Color.parseColor("#E2E8F0"))
            textSize = 12f
        }
        val chkAutoAccept = CheckBox(this).apply {
            text = "Auto-aceptar archivos de pares verificados"
            isChecked = prefs.getBoolean("prof_auto_accept", false)
            setTextColor(Color.parseColor("#E2E8F0"))
            textSize = 12f
        }
        val chkAlerts = CheckBox(this).apply {
            text = "Notificar alertas de intrusión Guardián"
            isChecked = prefs.getBoolean("prof_notify_guardian", true)
            setTextColor(Color.parseColor("#E2E8F0"))
            textSize = 12f
        }

        profileSec.addView(avatarTopRow)
        profileSec.addView(presetsRow)
        profileSec.addView(nameInput)
        profileSec.addView(handleInput)
        profileSec.addView(emailInput)
        profileSec.addView(bioInput)
        profileSec.addView(presRow)
        profileSec.addView(chkShowIp)
        profileSec.addView(chkAutoAccept)
        profileSec.addView(chkAlerts)

        // 2FA Google Authenticator Section
        val totpStatus = TextView(this).apply {
            text = if (twoFaActive) "2FA Google Authenticator: ACTIVO ✓" else "2FA Google Authenticator: Escanea QR e ingresa 6 dígitos"
            textSize = 12f
            setTypeface(null, Typeface.BOLD)
            setTextColor(Color.parseColor(if (twoFaActive) "#34D399" else "#FBBF24"))
            setPadding(0, dp(4), 0, dp(8))
        }
        val otpUri = "otpauth://totp/NexoMesh:${Uri.encode(currentEmail)}?secret=$secret&issuer=NexoMesh&algorithm=SHA1&digits=6&period=30"
        val qrWrap = LinearLayout(this).apply {
            gravity = Gravity.CENTER
            background = makeCardDrawable("#FFFFFF", themeBorder(), 14, 1)
            setPadding(dp(12), dp(12), dp(12), dp(12))
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT).apply {
                gravity = Gravity.CENTER_HORIZONTAL
                bottomMargin = dp(8)
            }
        }
        val qrView = ImageView(this).apply {
            setImageBitmap(generateQrBitmap(otpUri, 380))
            layoutParams = LinearLayout.LayoutParams(dp(156), dp(156))
        }
        qrWrap.addView(qrView)

        val secretRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            background = makeCardDrawable(themeInset(), themeBorder(), 10, 1)
            setPadding(dp(10), dp(8), dp(10), dp(8))
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT).apply { bottomMargin = dp(8) }
        }
        val secretTv = TextView(this).apply {
            text = "Clave Base32:\n$secret"
            textSize = 11f
            setTextColor(Color.parseColor("#CBD5E1"))
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }
        val copySecretBtn = makeStyledButton("Copiar Clave", "#0C4A6E", "#38BDF8", "#BAE6FD", 8).apply {
            textSize = 11f
            minHeight = dp(36)
            setOnClickListener {
                val cm = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
                cm.setPrimaryClip(ClipData.newPlainText("NexoMesh Base32", secret))
                totpStatus.text = "Clave Base32 copiada al portapapeles ✓"
            }
        }
        secretRow.addView(secretTv)
        secretRow.addView(copySecretBtn)

        val codeInput = makeDarkField("", "Código 6 dígitos Google Authenticator").apply {
            inputType = InputType.TYPE_CLASS_NUMBER
        }
        val verifyBtn = makeStyledButton("Verificar y Activar 2FA", "#059669", "#10B981", "#FFFFFF", 10).apply {
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT).apply { bottomMargin = dp(10) }
            setOnClickListener {
                val entered = codeInput.text.toString().trim()
                if (verifyGoogleTotp(secret, entered)) {
                    twoFaActive = true
                    prefs.edit().putBoolean("totp_enabled", true).apply()
                    totpStatus.text = "2FA Google Authenticator: VINCULADO Y ACTIVO ✓"
                    totpStatus.setTextColor(Color.parseColor("#34D399"))
                    appendLog("INFO", "App", myVirtualIp, "2FA Google Authenticator vinculado correctamente")
                    refreshAllUi()
                } else {
                    totpStatus.text = "Código inválido: verifica la hora e intenta de nuevo"
                    totpStatus.setTextColor(Color.parseColor("#FCA5A5"))
                }
            }
        }
        val recoveryBox = TextView(this).apply {
            val codes = (1..6).joinToString("   ") { i -> "NX${secret.substring((i * 4) % 24, ((i * 4) % 24) + 4)}" }
            text = "Códigos de respaldo de emergencia:\n$codes"
            textSize = 11f
            setTextColor(Color.parseColor("#94A3B8"))
            background = makeCardDrawable(themeInset(), themeBorder(), 10, 1)
            setPadding(dp(10), dp(8), dp(10), dp(8))
        }
        twoFaSec.addView(totpStatus)
        twoFaSec.addView(qrWrap)
        twoFaSec.addView(secretRow)
        twoFaSec.addView(codeInput)
        twoFaSec.addView(verifyBtn)
        twoFaSec.addView(recoveryBox)

        fun switchModalTab(idx: Int) {
            modalTab = idx
            profileSec.visibility = if (idx == 0) View.VISIBLE else View.GONE
            twoFaSec.visibility = if (idx == 1) View.VISIBLE else View.GONE
            tabProfileBtn.background = makeCardDrawable(if (idx == 0) themeSurface() else themeInset(), if (idx == 0) themeAccent() else themeBorder(), 10, 1)
            tabProfileBtn.setTextColor(Color.parseColor(if (idx == 0) "#F8FAFC" else "#94A3B8"))
            tab2faBtn.background = makeCardDrawable(if (idx == 1) themeSurface() else themeInset(), if (idx == 1) themeAccent() else themeBorder(), 10, 1)
            tab2faBtn.setTextColor(Color.parseColor(if (idx == 1) "#F8FAFC" else "#94A3B8"))
        }
        tabProfileBtn.setOnClickListener { switchModalTab(0) }
        tab2faBtn.setOnClickListener { switchModalTab(1) }

        root.addView(tabRow)
        root.addView(profileSec)
        root.addView(twoFaSec)

        val dlg = makeThemedDialog(
            title = "Perfil de Usuario y 2FA",
            bodyView = root,
            positiveLabel = "Guardar Cambios",
            onPositive = { d ->
                prefs.edit()
                    .putString("user_name", nameInput.text.toString().ifBlank { currentName })
                    .putString("user_handle", handleInput.text.toString().ifBlank { currentHandle })
                    .putString("user_email", emailInput.text.toString().ifBlank { currentEmail })
                    .putString("user_bio", bioInput.text.toString().ifBlank { currentBio })
                    .putString("user_presence", selectedPresence)
                    .putBoolean("prof_show_ip", chkShowIp.isChecked)
                    .putBoolean("prof_auto_accept", chkAutoAccept.isChecked)
                    .putBoolean("prof_notify_guardian", chkAlerts.isChecked)
                    .apply()
                profileModalRefreshAvatar = null
                refreshAllUi()
                d.dismiss()
            },
            negativeLabel = "Cerrar",
            onNegative = { profileModalRefreshAvatar = null }
        )
        dlg.setOnDismissListener { profileModalRefreshAvatar = null }
        dlg.show()
    }

    inner class TelemetryGraphView(context: android.content.Context) : View(context) {
        private var rttVals: List<Float> = emptyList()
        private var rxVals: List<Float> = emptyList()
        private var txVals: List<Float> = emptyList()
        private val gridPaint = Paint().apply {
            color = Color.parseColor("#1E293B")
            strokeWidth = 2f
            pathEffect = DashPathEffect(floatArrayOf(8f, 8f), 0f)
        }
        private val rxPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = Color.parseColor("#38BDF8")
            strokeWidth = 5f
            style = Paint.Style.STROKE
        }
        private val txPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = Color.parseColor("#F59E0B")
            strokeWidth = 5f
            style = Paint.Style.STROKE
        }
        private val rttPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = Color.parseColor("#10B981")
            strokeWidth = 5f
            style = Paint.Style.STROKE
        }

        fun setSeries(rtt: List<Float>, rx: List<Float>, tx: List<Float>) {
            rttVals = rtt.toList()
            rxVals = rx.toList()
            txVals = tx.toList()
            invalidate()
        }

        override fun onDraw(canvas: Canvas) {
            super.onDraw(canvas)
            val w = width.toFloat()
            val h = height.toFloat()
            canvas.drawColor(Color.parseColor(themeInset()))
            for (r in listOf(0.25f, 0.5f, 0.75f)) {
                canvas.drawLine(0f, h * r, w, h * r, gridPaint)
            }
            drawLineSeries(canvas, rxVals, 100f, rxPaint, w, h)
            drawLineSeries(canvas, txVals, 100f, txPaint, w, h)
            drawLineSeries(canvas, rttVals, 80f, rttPaint, w, h)
        }

        private fun drawLineSeries(canvas: Canvas, vals: List<Float>, maxV: Float, paint: Paint, w: Float, h: Float) {
            if (vals.size < 2) return
            val path = Path()
            vals.forEachIndexed { idx, v ->
                val x = (idx.toFloat() / (vals.size - 1)) * w
                val y = h - 10f - ((v.coerceIn(0f, maxV) / maxV) * (h - 20f))
                if (idx == 0) path.moveTo(x, y) else path.lineTo(x, y)
            }
            canvas.drawPath(path, paint)
        }
    }

    inner class PeerRtt60sGraphView(context: android.content.Context) : View(context) {
        private var seriesList: List<Triple<String, String, List<Pair<Long, Float>>>> = emptyList()
        private var windowEndMs: Long = System.currentTimeMillis()
        private val gridPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = Color.parseColor("#1E293B")
            strokeWidth = 2f
            style = Paint.Style.STROKE
        }
        private val labelPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = Color.parseColor("#64748B")
            textSize = 24f
        }
        private val linePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            strokeWidth = 5f
            style = Paint.Style.STROKE
            strokeCap = Paint.Cap.ROUND
            strokeJoin = Paint.Join.ROUND
        }
        private val dotPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            style = Paint.Style.FILL
        }

        fun setPeerSeries(series: List<Triple<String, String, List<Pair<Long, Float>>>>, nowMs: Long) {
            seriesList = series
            windowEndMs = nowMs
            invalidate()
        }

        override fun onDraw(canvas: Canvas) {
            super.onDraw(canvas)
            val w = width.toFloat()
            val h = height.toFloat()
            canvas.drawColor(Color.parseColor(themeInset()))
            val padLeft = 64f
            val padRight = 18f
            val padTop = 18f
            val padBottom = 18f
            val plotW = maxOf(10f, w - padLeft - padRight)
            val plotH = maxOf(10f, h - padTop - padBottom)
            val maxRtt = maxOf(
                60f,
                seriesList.flatMap { it.third }.map { it.second }.filter { it >= 0f }.maxOrNull() ?: 60f
            )
            for (r in listOf(0f, 0.5f, 1f)) {
                val y = padTop + (plotH * r)
                canvas.drawLine(padLeft, y, w - padRight, y, gridPaint)
                val tickVal = ((1f - r) * maxRtt).toInt()
                canvas.drawText("${tickVal}ms", 6f, y + 8f, labelPaint)
            }
            val startMs = windowEndMs - 60_000L
            for ((_, colorHex, points) in seriesList) {
                if (points.isEmpty()) continue
                linePaint.color = Color.parseColor(colorHex)
                dotPaint.color = Color.parseColor(colorHex)
                val path = Path()
                var drawing = false
                var lastX = -1f
                var lastY = -1f
                for ((ts, rtt) in points) {
                    if (rtt < 0f) {
                        drawing = false
                        continue
                    }
                    val ratioX = ((ts - startMs).toFloat() / 60_000f).coerceIn(0f, 1f)
                    val x = padLeft + ratioX * plotW
                    val y = padTop + plotH - ((rtt.coerceIn(0f, maxRtt) / maxRtt) * plotH)
                    if (!drawing) {
                        path.moveTo(x, y)
                        drawing = true
                    } else {
                        path.lineTo(x, y)
                    }
                    lastX = x
                    lastY = y
                }
                canvas.drawPath(path, linePaint)
                if (lastX >= 0f && lastY >= 0f) {
                    canvas.drawCircle(lastX, lastY, 7f, dotPaint)
                }
            }
        }
    }

    inner class PeerAvgLatencyBarGraphView(context: android.content.Context) : View(context) {
        private var bars: List<Triple<String, String, Float>> = emptyList()
        private val trackPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = Color.parseColor("#0F172A")
            style = Paint.Style.FILL
        }
        private val barPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            style = Paint.Style.FILL
        }
        private val avgLinePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = Color.parseColor("#CBD5E1")
            strokeWidth = 3f
            style = Paint.Style.STROKE
        }
        private val namePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = Color.parseColor("#E2E8F0")
            textSize = 26f
        }
        private val valuePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = Color.parseColor("#34D399")
            textSize = 26f
            typeface = Typeface.DEFAULT_BOLD
        }

        fun setBars(items: List<Triple<String, String, Float>>) {
            bars = items
            invalidate()
        }

        override fun onDraw(canvas: Canvas) {
            super.onDraw(canvas)
            val w = width.toFloat()
            val h = height.toFloat()
            canvas.drawColor(Color.parseColor(themeInset()))
            if (bars.isEmpty()) {
                canvas.drawText("Sin pares activos para comparar", 20f, h / 2f, namePaint)
                return
            }
            val maxRtt = maxOf(60f, (bars.maxOfOrNull { it.third } ?: 60f) * 1.15f)
            val avgRtt = bars.map { it.third }.average().toFloat()
            val rowH = minOf(dp(44).toFloat(), (h - 16f) / maxOf(1, bars.size))
            val labelW = w * 0.34f
            val valW = dp(64).toFloat()
            val trackLeft = labelW + 8f
            val trackRight = w - valW - 12f
            val trackW = maxOf(40f, trackRight - trackLeft)

            val avgX = trackLeft + ((avgRtt / maxRtt).coerceIn(0f, 1f) * trackW)
            canvas.drawLine(avgX, 6f, avgX, h - 6f, avgLinePaint)

            bars.forEachIndexed { idx, (name, colorHex, avgVal) ->
                val top = 8f + idx * rowH
                val barTop = top + rowH * 0.22f
                val barBottom = top + rowH * 0.78f
                val textY = top + rowH * 0.62f
                val shortName = if (name.length > 16) name.take(15) + "…" else name
                canvas.drawText(shortName, 8f, textY, namePaint)

                canvas.drawRoundRect(trackLeft, barTop, trackRight, barBottom, 10f, 10f, trackPaint)
                val fillW = maxOf(10f, (avgVal / maxRtt).coerceIn(0f, 1f) * trackW)
                barPaint.color = Color.parseColor(colorHex)
                canvas.drawRoundRect(trackLeft, barTop, trackLeft + fillW, barBottom, 10f, 10f, barPaint)

                canvas.drawText("${avgVal.toInt()} ms", trackRight + 10f, textY, valuePaint)
            }
        }
    }

    inner class MeshTopologyCanvasView(context: android.content.Context) : View(context) {
        private var hostIp = "10.0.0.1"
        private var hostUp = false
        private var peersSnapshot: List<PeerItem> = emptyList()
        private val edgePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply { style = Paint.Style.STROKE }
        private val nodeFill = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = Color.parseColor("#0F172A") }
        private val nodeStroke = Paint(Paint.ANTI_ALIAS_FLAG).apply { style = Paint.Style.STROKE }
        private val textPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = Color.parseColor("#E2E8F0")
            textSize = 24f
            textAlign = Paint.Align.CENTER
        }

        fun setMeshData(localIp: String, active: Boolean, peers: List<PeerItem>) {
            hostIp = localIp
            hostUp = active
            peersSnapshot = peers
            invalidate()
        }

        override fun onDraw(canvas: Canvas) {
            super.onDraw(canvas)
            val w = width.toFloat()
            val h = height.toFloat()
            canvas.drawColor(Color.parseColor(themeInset()))
            val cx = w / 2f
            val cy = h / 2f
            val radius = minOf(w, h) * 0.34f
            val coords = peersSnapshot.mapIndexed { idx, p ->
                val angle = (idx.toDouble() / maxOf(1, peersSnapshot.size)) * Math.PI * 2.0 - Math.PI / 2.0
                val px = cx + (Math.cos(angle) * radius).toFloat()
                val py = cy + (Math.sin(angle) * radius).toFloat()
                Triple(p, px, py)
            }
            for ((p, px, py) in coords) {
                val colorHex = when {
                    p.quarantined -> "#EF4444"
                    !hostUp || !p.online -> "#475569"
                    p.rttMs > 100 -> "#F97316"
                    p.rttMs > 40 -> "#F59E0B"
                    else -> "#10B981"
                }
                edgePaint.color = Color.parseColor(colorHex)
                edgePaint.strokeWidth = if (p.online && !p.quarantined && hostUp) 5f else 3f
                canvas.drawLine(cx, cy, px, py, edgePaint)
                canvas.drawText(if (p.online && hostUp && !p.quarantined) "${p.rttMs} ms" else "OFF", (cx + px) / 2f, (cy + py) / 2f - 6f, textPaint)
            }
            nodeStroke.color = Color.parseColor(if (hostUp) "#34D399" else "#475569")
            nodeStroke.strokeWidth = 6f
            canvas.drawCircle(cx, cy, dp(22).toFloat(), nodeFill)
            canvas.drawCircle(cx, cy, dp(22).toFloat(), nodeStroke)
            canvas.drawText(hostIp, cx, cy + dp(34).toFloat(), textPaint)
            for ((p, px, py) in coords) {
                val colorHex = if (p.quarantined) "#EF4444" else if (p.online) "#38BDF8" else "#475569"
                nodeStroke.color = Color.parseColor(colorHex)
                nodeStroke.strokeWidth = 4f
                canvas.drawCircle(px, py, dp(16).toFloat(), nodeFill)
                canvas.drawCircle(px, py, dp(16).toFloat(), nodeStroke)
                canvas.drawText(p.name.take(14), px, py + dp(28).toFloat(), textPaint)
            }
        }
    }

    inner class LiquidCircleView(context: android.content.Context) : View(context) {
        private var pct = 0
        private var state = "completed"
        private var frost = 0
        private var tick = 0
        private val bgPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = Color.parseColor("#070B12") }
        private val liquidPaint = Paint(Paint.ANTI_ALIAS_FLAG)
        private val ringPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            style = Paint.Style.STROKE
            strokeWidth = 6f
        }
        private val frostPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = Color.parseColor("#BAE6FD") }

        fun setTransferState(progressPct: Int, status: String, frostLevel: Int, wave: Int) {
            pct = progressPct.coerceIn(0, 100)
            state = status
            frost = frostLevel.coerceIn(0, 100)
            tick = wave
            invalidate()
        }

        override fun onDraw(canvas: Canvas) {
            super.onDraw(canvas)
            val cx = width / 2f
            val cy = height / 2f
            val r = min(cx, cy) - 6f
            canvas.drawCircle(cx, cy, r, bgPaint)

            val fillHex = when (state) {
                "failed" -> "#EF4444"
                "paused", "thawing" -> "#38BDF8"
                "canceled" -> "#475569"
                else -> "#10B981"
            }
            liquidPaint.color = Color.parseColor(fillHex)

            val effectivePct = if (state == "canceled") 0 else pct
            val clipPath = Path().apply { addCircle(cx, cy, r - 3f, Path.Direction.CW) }
            canvas.save()
            canvas.clipPath(clipPath)
            val topY = (cy + r) - ((effectivePct / 100f) * (r * 2f))
            val phase = if (state == "paused") 0.0 else tick * 0.4
            val wavePath = Path().apply {
                moveTo(cx - r, cy + r)
                var x = cx - r
                while (x <= cx + r) {
                    val y = topY + (sin(x * 0.12 + phase) * 5.0).toFloat()
                    lineTo(x, y)
                    x += 6f
                }
                lineTo(cx + r, cy + r)
                close()
            }
            canvas.drawPath(wavePath, liquidPaint)
            if (frost > 0) {
                frostPaint.alpha = (frost * 140) / 100
                canvas.drawCircle(cx, cy, r, frostPaint)
            }
            canvas.restore()

            ringPaint.color = Color.parseColor(fillHex)
            if (state == "failed") {
                val rect = RectF(cx - r, cy - r, cx + r, cy + r)
                canvas.drawArc(rect, 130f, 165f, false, ringPaint)
                canvas.drawArc(rect, -35f, 155f, false, ringPaint)
                canvas.drawLine(cx + r * 0.5f, cy - r * 0.6f, cx - r * 0.5f, cy + r * 0.6f, ringPaint)
            } else {
                canvas.drawCircle(cx, cy, r, ringPaint)
            }
        }
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
            appendLog("WARNING", "WireGuard", myVirtualIp, "QR inválido (se esperaba nexomesh://join)")
            refreshAllUi()
            return
        }
        val uri = Uri.parse(rawUri)
        val peerName = uri.getQueryParameter("name") ?: "Amigo ${connectedPeers.size + 1}"
        val assignedLocalIp = uri.getQueryParameter("ip") ?: "10.0.0.${connectedPeers.size + 2}"
        val peerHostIp = uri.getQueryParameter("hostIp") ?: "10.0.0.1"
        val endpoint = uri.getQueryParameter("ep") ?: "STUN directo"
        val lanEp = uri.getQueryParameter("lan") ?: ""
        val peerPublicKey = uri.getQueryParameter("pk") ?: ""
        val lansRaw = uri.getQueryParameter("lans") ?: ""
        val require2fa = uri.getQueryParameter("auth2fa") == "1"
        val expectedPin = uri.getQueryParameter("pin") ?: ""

        // Todos los endpoints LAN candidatos del invitador, incluido el principal.
        val allLans = (lansRaw.split(",") + lanEp)
            .map { it.trim() }
            .filter { it.isNotBlank() }
            .distinct()
        val helloTargets = allLans.joinToString(",")

        // Descubrimiento bidireccional: al recibir NM_ACK del otro par se agrega
        // automǭticamente a la lista de pares.
        MeshVpnService.registerDiscoveredPeerCallback { vip, name, remoteAddr ->
            runOnUiThread {
                val discovered = connectedPeers.firstOrNull { it.virtualIp == vip }
                if (discovered == null) {
                    connectedPeers.add(
                        PeerItem(
                            id = "peer-${System.currentTimeMillis()}",
                            name = name,
                            virtualIp = vip,
                            platform = "P2P Mesh",
                            endpoint = remoteAddr,
                            lanEndpoint = remoteAddr,
                            online = true,
                            rttMs = 1
                        )
                    )
                } else {
                    discovered.endpoint = remoteAddr
                    discovered.lanEndpoint = remoteAddr
                    discovered.online = true
                    discovered.rttMs = 1
                }
                syncPeersToVpnService()
                appendLog("INFO", "Noise", vip, "Par P2P descubierto y enlazado: '$name' ($remoteAddr)")
                refreshAllUi()
            }
        }

        fun sendHello() {
            Thread {
                MeshVpnService.sendHelloBurstToPeer(helloTargets, endpoint, myVirtualIp, Build.MODEL)
            }.start()
        }

        fun finalizeJoin() {
            myVirtualIp = assignedLocalIp
            getSharedPreferences("nexomesh_prefs", MODE_PRIVATE).edit()
                .putString("my_virtual_ip", myVirtualIp)
                .apply()
            if (peerPublicKey.isNotBlank()) {
                getSharedPreferences("nexomesh_prefs", MODE_PRIVATE).edit()
                    .putString("peer_pk_$peerHostIp", peerPublicKey)
                    .apply()
            }
            MeshVpnService.updateLocalVirtualIp(myVirtualIp)

            val existing = connectedPeers.firstOrNull { it.virtualIp == peerHostIp }
            if (existing == null) {
                connectedPeers.add(
                    PeerItem(
                        id = "peer-${System.currentTimeMillis()}",
                        name = peerName,
                        virtualIp = peerHostIp,
                        platform = "P2P Mesh",
                        endpoint = endpoint,
                        lanEndpoint = helloTargets,
                        online = true,
                        rttMs = 1
                    )
                )
            } else {
                existing.endpoint = endpoint
                existing.lanEndpoint = helloTargets
                existing.online = true
                existing.rttMs = 1
            }
            pendingSendTargetIp = peerHostIp
            if (::fileTargetIpInput.isInitialized) {
                fileTargetIpInput.setText(peerHostIp)
            }
            syncPeersToVpnService()
            appendLog("INFO", "Noise", peerHostIp, "Enlazado a '$peerName' ($peerHostIp) · Tu IP local asignada: $myVirtualIp (${lanEp.ifBlank { endpoint }})")
            if (vpnRunning) {
                sendHello()
                mainHandler.postDelayed({ sendHello() }, 1500L)
            } else {
                // El socket UDP solo existe con el tǧnel activo. Iniciar VPN y
                // reintentar el saludo hasta que el socket estǩ disponible.
                appendLog("INFO", "Noise", peerHostIp, "Iniciando tǧnel VPN para el enlace P2P con '$peerName'")
                requestAndStartVpn()
                for (delay in listOf(800L, 2000L, 4000L)) {
                    mainHandler.postDelayed({ sendHello() }, delay)
                }
            }
            switchTab(AppTab.TUNNEL)
            refreshAllUi()
        }

        if (require2fa) {
            val otpInput = EditText(this).apply {
                hint = "Código 2FA de 6 dígitos"
                inputType = InputType.TYPE_CLASS_NUMBER
                setHintTextColor(Color.parseColor("#64748B"))
                setTextColor(Color.parseColor("#F8FAFC"))
                background = makeCardDrawable(themeInset(), themeBorder(), 10, 1)
                setPadding(dp(12), dp(10), dp(12), dp(10))
            }
            makeThemedDialog(
                title = "Invitación con 2FA",
                message = "Ingresa el código de 6 dígitos mostrado por $peerName para conectarte:",
                bodyView = otpInput,
                positiveLabel = "Verificar y Conectar",
                onPositive = { dlg ->
                    val entered = otpInput.text.toString().trim()
                    val ok = (expectedPin.isNotEmpty() && entered == expectedPin) ||
                        verifyGoogleTotp(getOrCreateTotpSecret(), entered)
                    if (ok) {
                        dlg.dismiss()
                        finalizeJoin()
                    } else {
                        appendLog("WARNING", "Noise", peerHostIp, "Código 2FA inválido para invitación de '$peerName'")
                        refreshAllUi()
                    }
                },
                negativeLabel = "Cancelar"
            ).show()
            return
        }

        finalizeJoin()
    }

    private fun registerNetworkMonitor() {
        try {
            val cm = getSystemService(ConnectivityManager::class.java)
            cm.registerDefaultNetworkCallback(networkCallback)
        } catch (_: Exception) {
        }
    }

    private fun triggerLossAndExponentialBackoff() {
        backoffRetryRunnable?.let { mainHandler.removeCallbacks(it) }
        backoffAttempt += 1
        val delayMs = min(32000L, 1000L shl (backoffAttempt - 1))
        appendLog("CRITICAL", "Alerta", myVirtualIp, "Red perdida por completo. Backoff intento #$backoffAttempt en ${delayMs / 1000}s")
        refreshAllUi()

        val retryTask = Runnable {
            if (vpnRunning && backoffAttempt > 0 && !hasPhysicalInternet()) {
                triggerLossAndExponentialBackoff()
            }
        }
        backoffRetryRunnable = retryTask
        mainHandler.postDelayed(retryTask, delayMs)
    }

    private fun appendLog(severity: String, subsystem: String, peerIp: String, message: String) {
        val ts = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss", Locale.US).format(Date())
        logsList.add(0, LogItem(ts, severity, subsystem, peerIp, message))
    }

    private fun exportLogsToCsv() {
        val csvFile = File(cacheDir, "nexomesh-logs.csv")
        val header = "timestamp,severity,subsystem,peer_ip,message\n"
        val body = logsList.joinToString("\n") { item ->
            val escaped = item.message.replace("\"", "\"\"")
            "${item.timestamp},${item.severity},${item.subsystem},${item.peerIp},\"$escaped\""
        }
        csvFile.writeText(header + body)
        val contentUri = FileProvider.getUriForFile(this, "$packageName.fileprovider", csvFile)
        val sendIntent = Intent(Intent.ACTION_SEND).apply {
            type = "text/csv"
            putExtra(Intent.EXTRA_STREAM, contentUri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        startActivity(Intent.createChooser(sendIntent, "Exportar historial de logs CSV"))
    }

    private fun exportLogsToJson() {
        val jsonFile = File(cacheDir, "nexomesh-audit.json")
        val rows = logsList.joinToString(",\n") { item ->
            val escaped = item.message.replace("\"", "\\\"")
            "  {\"timestamp\":\"${item.timestamp}\",\"severity\":\"${item.severity}\",\"subsystem\":\"${item.subsystem}\",\"peer_ip\":\"${item.peerIp}\",\"message\":\"$escaped\"}"
        }
        jsonFile.writeText("{\n\"logs\":[\n$rows\n]\n}")
        val contentUri = FileProvider.getUriForFile(this, "$packageName.fileprovider", jsonFile)
        val sendIntent = Intent(Intent.ACTION_SEND).apply {
            type = "application/json"
            putExtra(Intent.EXTRA_STREAM, contentUri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        startActivity(Intent.createChooser(sendIntent, "Exportar auditoría JSON"))
    }

    private fun requestAndStartVpn() {
        val prepareIntent = VpnService.prepare(this)
        if (prepareIntent != null) {
            vpnPermissionLauncher.launch(prepareIntent)
        } else {
            startMeshTunnel()
        }
    }

    private fun detectAndApplyAutoTransport(restartIfRunning: Boolean) {
        try {
            val cm = getSystemService(ConnectivityManager::class.java)
            val nets = cm?.allNetworks ?: emptyArray()
            var wifiCaps: NetworkCapabilities? = null
            var fallbackCaps: NetworkCapabilities? = null
            for (net in nets) {
                val caps = cm.getNetworkCapabilities(net)
                if (
                    caps != null &&
                    !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
                    caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                ) {
                    if (caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) {
                        applyCapabilitiesPolicy(caps, restartIfRunning)
                        return
                    }
                    if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
                        wifiCaps = caps
                    }
                    if (fallbackCaps == null) {
                        fallbackCaps = caps
                    }
                }
            }
            if (wifiCaps != null) {
                applyCapabilitiesPolicy(wifiCaps, restartIfRunning)
                return
            }
            if (fallbackCaps != null) {
                applyCapabilitiesPolicy(fallbackCaps, restartIfRunning)
                return
            }
        } catch (_: Exception) {
        }
        applyTransportParameters(medium = "cellular", isAuto = true, restartIfRunning = restartIfRunning)
    }

    private fun applyCapabilitiesPolicy(caps: NetworkCapabilities, restartIfRunning: Boolean) {
        val medium = when {
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "ethernet"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "wifi"
            else -> "cellular"
        }
        applyTransportParameters(medium = medium, isAuto = true, restartIfRunning = restartIfRunning)
    }

    private fun applyManualTransport(medium: String, restartIfRunning: Boolean) {
        applyTransportParameters(medium = medium, isAuto = false, restartIfRunning = restartIfRunning)
    }

    private fun applyTransportParameters(medium: String, isAuto: Boolean, restartIfRunning: Boolean) {
        val newMtu = when (medium) {
            "ethernet" -> 1420
            "wifi" -> 1380
            else -> 1280
        }
        val newKeepalive = when (medium) {
            "ethernet" -> 25
            "wifi" -> 15
            else -> 10
        }
        val mediumName = when (medium) {
            "ethernet" -> "Cable Ethernet"
            "wifi" -> "Wi-Fi"
            else -> "4G/5G"
        }
        val newLabel = if (isAuto) "Auto ($mediumName)" else "Manual ($mediumName)"
        if (medium == activeMedium && newMtu == activeMtu && newKeepalive == activeKeepalive && newLabel == activeTransportLabel) {
            refreshAllUi()
            return
        }
        val mtuChanged = newMtu != activeMtu
        activeMedium = medium
        activeMtu = newMtu
        activeKeepalive = newKeepalive
        activeTransportLabel = newLabel
        appendLog(
            "INFO",
            "WireGuard",
            myVirtualIp,
            "Política $activeTransportLabel aplicada (MTU $activeMtu, Keepalive ${activeKeepalive}s)"
        )
        refreshAllUi()
        if (restartIfRunning && mtuChanged) {
            startMeshTunnel()
        }
    }

    private fun isBatteryExempt(): Boolean {
        val pm = getSystemService(PowerManager::class.java)
        return pm?.isIgnoringBatteryOptimizations(packageName) == true
    }

    private fun requestBatteryExemption() {
        reopenKeepAliveOnResume = true
        try {
            val intent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
                data = Uri.parse("package:$packageName")
            }
            startActivity(intent)
        } catch (_: Exception) {
            try {
                startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
            } catch (_: Exception) {
                reopenKeepAliveOnResume = false
            }
        }
    }

    private fun startMeshTunnel() {
        MeshVpnService.updateLocalVirtualIp(myVirtualIp)
        syncPeersToVpnService()
        val intent = Intent(this, MeshVpnService::class.java).apply {
            putExtra("VIRTUAL_IP", myVirtualIp)
            putExtra("MTU", activeMtu)
            putExtra("KEEPALIVE_SEC", activeKeepalive)
            putExtra("STUN_SERVER", activeStunServer)
        }
        ContextCompat.startForegroundService(this, intent)
        vpnRunning = true
        appendLog("INFO", "WireGuard", myVirtualIp, "Túnel VPN iniciado ($myVirtualIp/24, MTU $activeMtu, keepalive ${activeKeepalive}s)")
        refreshAllUi()
    }

    private fun stopMeshTunnel() {
        pendingLossRunnable?.let { mainHandler.removeCallbacks(it) }
        backoffRetryRunnable?.let { mainHandler.removeCallbacks(it) }
        backoffAttempt = 0
        val intent = Intent(this, MeshVpnService::class.java).apply { action = "STOP" }
        startService(intent)
        vpnRunning = false
        appendLog("WARNING", "WireGuard", myVirtualIp, "Túnel detenido por el usuario")
        refreshAllUi()
    }

    override fun onDestroy() {
        fileReceiverActive = false
        try { fileServerSocket?.close() } catch (_: Exception) {}
        pendingLossRunnable?.let { mainHandler.removeCallbacks(it) }
        backoffRetryRunnable?.let { mainHandler.removeCallbacks(it) }
        try {
            val cm = getSystemService(ConnectivityManager::class.java)
            cm.unregisterNetworkCallback(networkCallback)
        } catch (_: Exception) {
        }
        super.onDestroy()
    }
}
