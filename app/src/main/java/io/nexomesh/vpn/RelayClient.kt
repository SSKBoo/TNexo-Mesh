package io.nexomesh.vpn

import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString
import org.json.JSONObject
import java.util.Base64

/**
 * Cliente de relay tipo DERP: envía frames NM1 cifrados por WSS al backend de
 * señalización cuando el UDP directo falla. El backend nunca ve el payload en claro.
 */
object RelayClient {
    private const val TAG = "NexoMeshRelay"
    private var socket: WebSocket? = null
    @Volatile
    private var connected = false
    private var currentUrl: String = ""
    private var identity: String = ""
    private val client = OkHttpClient()

    @Volatile
    var onFrameReceived: ((ByteArray) -> Unit)? = null

    fun connect(url: String, signingIdentity: String, signature: String) {
        connect(url, signingIdentity, signature, null)
    }

    fun connect(
        url: String,
        signingIdentity: String,
        fallbackSignature: String = "",
        signNonce: ((String) -> String)? = null
    ) {
        if (url.isBlank()) return
        close()
        currentUrl = url
        identity = signingIdentity
        val req = Request.Builder().url(url).build()
        socket = client.newWebSocket(req, object : WebSocketListener() {
            override fun onOpen(ws: WebSocket, response: Response) {
                if (signNonce == null) {
                    ws.send(JSONObject().apply {
                        put("type", "register")
                        put("from", signingIdentity)
                        put("signature", fallbackSignature)
                    }.toString())
                    connected = true
                    Log.i(TAG, "relay WS conectado (sin challenge)")
                }
            }

            override fun onMessage(ws: WebSocket, text: String) {
                try {
                    val msg = JSONObject(text)
                    when (msg.optString("type")) {
                        "challenge" -> {
                            val nonce = msg.optString("nonce")
                            val sig = signNonce?.invoke(nonce) ?: fallbackSignature
                            ws.send(JSONObject().apply {
                                put("type", "register")
                                put("from", signingIdentity)
                                put("signature", sig)
                            }.toString())
                            connected = true
                            Log.i(TAG, "relay WS registrado tras challenge")
                        }
                        "relay" -> {
                            val data = Base64.getDecoder().decode(msg.optString("data"))
                            onFrameReceived?.invoke(data)
                        }
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "mensaje relay inválido: ${e.message}")
                }
            }

            override fun onMessage(ws: WebSocket, bytes: ByteString) {
                val raw = bytes.toByteArray()
                if (raw.size >= 6 && raw[0] == 'N'.code.toByte() && raw[1] == 'M'.code.toByte() && raw[2] == '1'.code.toByte()) {
                    onFrameReceived?.invoke(raw)
                }
            }

            override fun onFailure(ws: WebSocket, t: Throwable, response: Response?) {
                connected = false
                Log.w(TAG, "relay WS falló: ${t.message}")
            }

            override fun onClosed(ws: WebSocket, code: Int, reason: String) {
                connected = false
            }
        })
    }

    fun send(frame: ByteArray): Boolean {
        if (!connected || socket == null) return false
        val json = JSONObject().apply {
            put("type", "relay")
            put("from", identity)
            put("data", Base64.getEncoder().encodeToString(frame))
        }.toString()
        return socket!!.send(json)
    }

    fun isConnected(): Boolean = connected

    fun close() {
        socket?.close(1000, "cerrando")
        socket = null
        connected = false
    }
}
