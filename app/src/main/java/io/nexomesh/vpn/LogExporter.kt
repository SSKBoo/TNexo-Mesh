package io.nexomesh.vpn

import android.content.Context
import android.content.Intent
import androidx.core.content.FileProvider
import java.io.File

/** Exportación de logs a CSV/JSON, separada de la Activity. */
class LogExporter(private val context: Context) {
    data class Row(val timestamp: String, val severity: String, val subsystem: String, val peerIp: String, val message: String)

    private fun escapeCsv(v: String) = "\"${v.replace("\"", "\"\"")}\""
    private fun escapeJson(v: String) = v.replace("\\", "\\\\").replace("\"", "\\\"")

    fun exportCsv(rows: List<Row>): Intent {
        val file = File(context.cacheDir, "nexomesh-logs.csv")
        val header = "timestamp,severity,subsystem,peer_ip,message\n"
        val body = rows.joinToString("\n") { r ->
            listOf(r.timestamp, r.severity, r.subsystem, r.peerIp, r.message).joinToString(",") { escapeCsv(it) }
        }
        file.writeText(header + body)
        return shareIntent(file, "text/csv", "Exportar historial de logs CSV")
    }

    fun exportJson(rows: List<Row>): Intent {
        val file = File(context.cacheDir, "nexomesh-audit.json")
        val body = rows.joinToString(",\n") { r ->
            "  {\"timestamp\":\"${escapeJson(r.timestamp)}\",\"severity\":\"${escapeJson(r.severity)}\"," +
            "\"subsystem\":\"${escapeJson(r.subsystem)}\",\"peer_ip\":\"${escapeJson(r.peerIp)}\"," +
            "\"message\":\"${escapeJson(r.message)}\"}"
        }
        file.writeText("{\n\"logs\":[\n$body\n]\n}")
        return shareIntent(file, "application/json", "Exportar auditoría JSON")
    }

    private fun shareIntent(file: File, type: String, chooser: String): Intent {
        val uri = FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file)
        return Intent(Intent.ACTION_SEND).apply {
            this.type = type
            putExtra(Intent.EXTRA_STREAM, uri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }.let { Intent.createChooser(it, chooser) }
    }
}
