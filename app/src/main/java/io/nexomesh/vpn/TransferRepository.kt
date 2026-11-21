package io.nexomesh.vpn

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

/**
 * Persistencia ligera del historial de transferencias y pares enlazados.
 * Usa SharedPreferences + org.json (incluido en Android, sin dependencias nuevas).
 * El historial sobrevive al cierre de la app y a la recreación de la Activity.
 */
class TransferRepository(context: Context) {
    private val prefs = context.getSharedPreferences("nexomesh_v1_state", Context.MODE_PRIVATE)

    data class TransferRow(
        val id: String, val fileName: String, val sizeBytes: Long, val direction: String,
        val peerIp: String, val status: String, val progressPct: Int, val errorReason: String?,
        val localPath: String?, val isFolder: Boolean, val channel: String, val timestamp: Long
    )

    data class PeerRow(
        val id: String, val name: String, val virtualIp: String, val platform: String,
        val endpoint: String, val lanEndpoint: String, val quarantined: Boolean,
        val quarantineReason: String?, val rttMs: Int
    )

    fun saveTransfers(rows: List<TransferRow>) {
        val arr = JSONArray()
        rows.forEach { r ->
            arr.put(JSONObject().apply {
                put("id", r.id); put("fileName", r.fileName); put("sizeBytes", r.sizeBytes)
                put("direction", r.direction); put("peerIp", r.peerIp); put("status", r.status)
                put("progressPct", r.progressPct); put("errorReason", r.errorReason ?: "")
                put("localPath", r.localPath ?: ""); put("isFolder", r.isFolder)
                put("channel", r.channel); put("timestamp", r.timestamp)
            })
        }
        prefs.edit().putString("transfers", arr.toString()).apply()
    }

    fun loadTransfers(): List<TransferRow> = try {
        val arr = JSONArray(prefs.getString("transfers", "[]") ?: "[]")
        (0 until arr.length()).map { i ->
            val o = arr.getJSONObject(i)
            TransferRow(
                id = o.optString("id"), fileName = o.optString("fileName"),
                sizeBytes = o.optLong("sizeBytes"), direction = o.optString("direction"),
                peerIp = o.optString("peerIp"), status = o.optString("status"),
                progressPct = o.optInt("progressPct"), errorReason = o.optString("errorReason").ifBlank { null },
                localPath = o.optString("localPath").ifBlank { null }, isFolder = o.optBoolean("isFolder"),
                channel = o.optString("channel"), timestamp = o.optLong("timestamp")
            )
        }
    } catch (_: Exception) { emptyList() }

    fun savePeers(rows: List<PeerRow>) {
        val arr = JSONArray()
        rows.forEach { r ->
            arr.put(JSONObject().apply {
                put("id", r.id); put("name", r.name); put("virtualIp", r.virtualIp)
                put("platform", r.platform); put("endpoint", r.endpoint); put("lanEndpoint", r.lanEndpoint)
                put("quarantined", r.quarantined); put("quarantineReason", r.quarantineReason ?: "")
                put("rttMs", r.rttMs)
            })
        }
        prefs.edit().putString("peers", arr.toString()).apply()
    }

    fun loadPeers(): List<PeerRow> = try {
        val arr = JSONArray(prefs.getString("peers", "[]") ?: "[]")
        (0 until arr.length()).map { i ->
            val o = arr.getJSONObject(i)
            PeerRow(
                id = o.optString("id"), name = o.optString("name"), virtualIp = o.optString("virtualIp"),
                platform = o.optString("platform"), endpoint = o.optString("endpoint"),
                lanEndpoint = o.optString("lanEndpoint"), quarantined = o.optBoolean("quarantined"),
                quarantineReason = o.optString("quarantineReason").ifBlank { null }, rttMs = o.optInt("rttMs")
            )
        }
    } catch (_: Exception) { emptyList() }
}
