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
import org.json.JSONObject
import java.util.Base64

/**
 * Cliente de relay tipo DERP: envía frames NM1 cifrados por WSS al backend de
 * señalización cuando el UDP directo falla. El backend nunca ve el payload en claro.
 */
object RelayClient {
    private const val TAG = "NexoMeshRelay"
    private var socket: WebSocket? = null
    private var connected = false
    private var currentUrl: String = ""
    private var identity: String = ""
    private val client = OkHttpClient()

    @Volatile
    var onFrameReceived: ((ByteArray) -> Unit)? = null

    fun connect(url: String, signingIdentity: String, signature: String) {
        currentUrl = url
        identity = signingIdentity
        val req = Request.Builder().url(url).build()
        socket = client.newWebSocket(req, object : WebSocketListener() {
            override fun onOpen(ws: WebSocket, response: Response) {
                ws.send(JSONObject().apply {
                    put("type", "register")
                    put("from", signingIdentity)
                    // El backend valida la firma del challenge; aquí registramos
                    // la identidad de firma. El challenge-response se completó en
                    // el flujo de señalización (ver docs/KEY_MODEL.md).
                    put("signature", signature)
                }.toString())
                connected = true
                Log.i(TAG, "relay WS conectado")
            }

            override fun onMessage(ws: WebSocket, text: String) {
                try {
                    val msg = JSONObject(text)
                    if (msg.optString("type") == "relay") {
                        val data = Base64.getDecoder().decode(msg.optString("data"))
                        onFrameReceived?.invoke(data)
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "mensaje relay inválido: ${e.message}")
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
