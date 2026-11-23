package io.nexomesh.vpn

import android.util.Log
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString
import org.json.JSONObject
import java.util.Base64

/**
 * Cliente DERP dirigido (NM2 / relay `to`): vincula nodeKey + signingKey
 * en el handshake de señalización y nunca hace broadcast sin destinatario.
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
        connect(url, signingIdentity, signature, "", "", null)
    }

    fun connect(
        url: String,
        signingIdentity: String,
        fallbackSignature: String = "",
        nodeKey: String = "",
        bindingSignature: String = "",
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
                        if (nodeKey.isNotBlank() && bindingSignature.isNotBlank()) {
                            put("nodeKey", nodeKey)
                            put("bindingSignature", bindingSignature)
                        }
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
                                if (nodeKey.isNotBlank() && bindingSignature.isNotBlank()) {
                                    put("nodeKey", nodeKey)
                                    put("bindingSignature", bindingSignature)
                                }
                            }.toString())
                            connected = true
                            Log.i(TAG, "relay WS registrado con identidad vinculada")
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
                if (raw.size >= 6) {
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

    /** Envía frame dirigido como binario NM2 (32B dstKey + payload) o JSON `relay` con `to` explícito. */
    fun send(frame: ByteArray, targetSigningKey: String = ""): Boolean {
        val ws = socket
        if (!connected || ws == null || targetSigningKey.isBlank()) return false
        try {
            val dstRaw = Base64.getDecoder().decode(targetSigningKey)
            if (dstRaw.size == 32) {
                val nm2 = ByteArray(3 + 32 + frame.size)
                nm2[0] = 'N'.code.toByte()
                nm2[1] = 'M'.code.toByte()
                nm2[2] = '2'.code.toByte()
                System.arraycopy(dstRaw, 0, nm2, 3, 32)
                System.arraycopy(frame, 0, nm2, 35, frame.size)
                return ws.send(ByteString.of(*nm2))
            }
        } catch (_: Exception) {
        }
        val json = JSONObject().apply {
            put("type", "relay")
            put("from", identity)
            put("to", targetSigningKey)
            put("data", Base64.getEncoder().encodeToString(frame))
        }.toString()
        return ws.send(json)
    }

    fun isConnected(): Boolean = connected

    fun close() {
        socket?.close(1000, "cerrando")
        socket = null
        connected = false
    }
}
