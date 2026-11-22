package io.nexomesh.vpn

import android.content.Context
import android.os.Environment
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.DataInputStream
import java.io.File
import java.io.FileOutputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.MessageDigest

/**
 * Receptor TCP P2P en :51821.
 *
 * Vive en el proceso de la app (no en la Activity), así que sigue escuchando
 * cuando la pantalla se recrea o pasa a segundo plano. Confirma cada transferencia
 * con NEXOMESH_ACK|OK|<bytes>|<sha256> para que el emisor solo marque "completado"
 * cuando el destino recibió y verificó los bytes.
 */
object FileTransferCore {
    data class Received(
        val name: String,
        val size: Long,
        val sha256: String,
        val senderIp: String,
        val localPath: String?,
        val isFolder: Boolean,
        val fileCount: Int
    )

    var onReceived: ((Received) -> Unit)? = null
    var onStatus: ((String) -> Unit)? = null

    /** La Activity la usa para redirigir a una carpeta SAF elegida por el usuario. */
    var openOutput: ((String) -> OutputStream?)? = null

    @Volatile
    var running: Boolean = false
        private set

    private var server: ServerSocket? = null
    private var saveDir: File? = null

    fun start(context: Context) {
        if (running) return
        running = true
        saveDir = File(context.getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS), "NexoMesh").apply { mkdirs() }
        Thread {
            try {
                val srv = ServerSocket().apply {
                    reuseAddress = true
                    bind(InetSocketAddress(51821))
                }
                server = srv
                onStatus?.invoke("listening")
                while (running && !srv.isClosed) {
                    val client = srv.accept()
                    Thread { handleClient(client) }.apply { name = "NexoMesh-FileClient" }.start()
                }
            } catch (e: Exception) {
                onStatus?.invoke("error: ${e.message}")
            } finally {
                running = false
                server = null
            }
        }.apply { name = "NexoMesh-FileReceiver" }.start()
    }

    fun stop() {
        running = false
        try { server?.close() } catch (_: Exception) {}
        server = null
    }

    private fun handleClient(client: Socket) {
        try {
            client.soTimeout = 120_000
            client.use { sock ->
                val dis = DataInputStream(BufferedInputStream(sock.getInputStream(), 65_536))
                val magic = readLine(dis)
                val senderIp = sock.inetAddress?.hostAddress ?: "10.0.0.x"
                val buf = ByteArray(65_536)
                when (magic) {
                    "NEXOMESH_FILE" -> receiveFile(sock, dis, buf, senderIp)
                    "NEXOMESH_FOLDER" -> receiveFolder(sock, dis, buf, senderIp)
                }
            }
        } catch (e: Exception) {
            onStatus?.invoke("client error: ${e.message}")
        }
    }

    private fun receiveFile(sock: Socket, dis: DataInputStream, buf: ByteArray, senderIp: String) {
        val rawName = readLine(dis).ifBlank { "recibido-${System.currentTimeMillis()}" }
        val safeName = File(rawName).name
        val declaredSize = (readLine(dis).toLongOrNull() ?: 0L).coerceIn(0L, 2L * 1024 * 1024 * 1024)
        val digest = MessageDigest.getInstance("SHA-256")
        val safOut = openOutput?.invoke(safeName)
        val outFile = File(saveDir, safeName)
        val target = safOut ?: FileOutputStream(outFile)
        var received = 0L
        BufferedOutputStream(target, 65_536).use { bos ->
            while (received < declaredSize) {
                val chunk = dis.read(buf, 0, minOf(buf.size.toLong(), declaredSize - received).toInt())
                if (chunk <= 0) break
                bos.write(buf, 0, chunk)
                digest.update(buf, 0, chunk)
                received += chunk
            }
            bos.flush()
        }
        val sha = hex(digest.digest())
        sendAck(sock, received, sha)
        onReceived?.invoke(
            Received(safeName, received, sha, senderIp, if (safOut == null) outFile.absolutePath else null, false, 1)
        )
    }

    private fun receiveFolder(sock: Socket, dis: DataInputStream, buf: ByteArray, senderIp: String) {
        val rootName = File(readLine(dis).ifBlank { "Carpeta-${System.currentTimeMillis()}" }).name
        val count = readLine(dis).toIntOrNull() ?: 0
        val digest = MessageDigest.getInstance("SHA-256")
        var totalBytes = 0L
        var firstPath: String? = null
        repeat(count.coerceAtMost(5000)) { i ->
            val rawRel = readLine(dis).replace("\\", "/").trimStart('/')
            val safeRel = rawRel.split('/').filter { it.isNotBlank() && it != ".." && it != "." }
                .joinToString("/").ifBlank { "$rootName/archivo-$i" }
            val declaredSize = (readLine(dis).toLongOrNull() ?: 0L).coerceIn(0L, 2L * 1024 * 1024 * 1024)
            val safOut = openOutput?.invoke(safeRel)
            val outFile = File(saveDir, safeRel)
            if (safOut == null) outFile.parentFile?.mkdirs()
            val target = safOut ?: FileOutputStream(outFile)
            var received = 0L
            BufferedOutputStream(target, 65_536).use { bos ->
                while (received < declaredSize) {
                    val chunk = dis.read(buf, 0, minOf(buf.size.toLong(), declaredSize - received).toInt())
                    if (chunk <= 0) break
                    bos.write(buf, 0, chunk)
                    digest.update(buf, 0, chunk)
                    received += chunk
                }
                bos.flush()
            }
            if (firstPath == null && safOut == null) firstPath = outFile.absolutePath
            totalBytes += received
        }
        val sha = hex(digest.digest())
        sendAck(sock, totalBytes, sha)
        onReceived?.invoke(
            Received("$rootName/ ($count arch.)", totalBytes, sha, senderIp, firstPath, true, count)
        )
    }

    private fun sendAck(sock: Socket, bytes: Long, sha256: String) {
        try {
            val ack = "NEXOMESH_ACK|OK|$bytes|$sha256\n".toByteArray(Charsets.UTF_8)
            sock.getOutputStream().write(ack)
            sock.getOutputStream().flush()
        } catch (_: Exception) {
        }
    }

    private fun readLine(dis: DataInputStream): String {
        val sb = StringBuilder()
        while (true) {
            val b = dis.read()
            if (b == -1 || b == '\n'.code) break
            if (b != '\r'.code) sb.append(b.toChar())
        }
        return sb.toString()
    }

    /** Guarda un archivo recibido cifrado dentro de un frame NM1 (vía Relay/UDP). */
    fun saveRelayedFile(context: Context, senderIp: String, rawName: String, data: ByteArray) {
        if (saveDir == null) {
            saveDir = File(context.getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS), "NexoMesh").apply { mkdirs() }
        }
        val safeName = File(rawName).name.ifBlank { "recibido-${System.currentTimeMillis()}" }
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(data)
        val sha = hex(digest.digest())
        val safOut = openOutput?.invoke(safeName)
        val outFile = File(saveDir, safeName)
        val target = safOut ?: FileOutputStream(outFile)
        target.use { os ->
            os.write(data)
            os.flush()
        }
        onReceived?.invoke(
            Received(safeName, data.size.toLong(), sha, senderIp, if (safOut == null) outFile.absolutePath else null, false, 1)
        )
    }

    private fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }
}
