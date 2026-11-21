package io.nexomesh.vpn

import android.content.Context
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** Utilidades TOTP (RFC 6238) sin estado de UI. */
object TotpHelper {
    private const val PREFS = "nexomesh_prefs"
    private const val KEY_SECRET = "totp_secret"
    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    fun getOrCreateSecret(context: Context): String {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        prefs.getString(KEY_SECRET, null)?.takeIf { it.isNotBlank() }?.let { return it }
        val bytes = ByteArray(20)
        SecureRandom().nextBytes(bytes)
        val secret = encodeBase32(bytes)
        prefs.edit().putString(KEY_SECRET, secret).apply()
        return secret
    }

    private fun encodeBase32(bytes: ByteArray): String {
        val sb = StringBuilder()
        var buffer = 0
        var bits = 0
        for (b in bytes) {
            buffer = (buffer shl 8) or (b.toInt() and 0xFF)
            bits += 8
            while (bits >= 5) {
                sb.append(ALPHABET[(buffer ushr (bits - 5)) and 0x1F])
                bits -= 5
            }
        }
        if (bits > 0) sb.append(ALPHABET[(buffer shl (5 - bits)) and 0x1F])
        return sb.toString()
    }

    fun decodeBase32(secret: String): ByteArray {
        val clean = secret.trim().uppercase().replace("=", "").replace(" ", "")
        var buffer = 0
        var bits = 0
        val out = mutableListOf<Byte>()
        for (c in clean) {
            val idx = ALPHABET.indexOf(c)
            if (idx < 0) continue
            buffer = (buffer shl 5) or idx
            bits += 5
            if (bits >= 8) {
                out.add(((buffer ushr (bits - 8)) and 0xFF).toByte())
                bits -= 8
            }
        }
        return out.toByteArray()
    }

    fun verify(secret: String, code: String, windowSeconds: Int = 30): Boolean {
        if (code.length != 6) return false
        val key = decodeBase32(secret)
        val counter = System.currentTimeMillis() / 1000L / windowSeconds
        for (delta in -1..1) {
            if (generate(key, counter + delta) == code) return true
        }
        return false
    }

    private fun generate(key: ByteArray, counter: Long): String {
        val msg = ByteArray(8)
        var c = counter
        for (i in 7 downTo 0) { msg[i] = (c and 0xFF).toByte(); c = c ushr 8 }
        val mac = Mac.getInstance("HmacSHA1").apply { init(SecretKeySpec(key, "HmacSHA1")) }
        val hash = mac.doFinal(msg)
        val offset = hash[hash.size - 1].toInt() and 0x0F
        val binary = ((hash[offset].toInt() and 0x7F) shl 24) or
            ((hash[offset + 1].toInt() and 0xFF) shl 16) or
            ((hash[offset + 2].toInt() and 0xFF) shl 8) or
            (hash[offset + 3].toInt() and 0xFF)
        return (binary % 1_000_000).toString().padStart(6, '0')
    }
}
