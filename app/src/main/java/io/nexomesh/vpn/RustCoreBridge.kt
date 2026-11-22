package io.nexomesh.vpn

object RustCoreBridge {
    private var loaded = false

    init {
        try {
            System.loadLibrary("nexomesh_core")
            loaded = true
        } catch (_: UnsatisfiedLinkError) {
            loaded = false
        }
    }

    fun isNativeReady(): Boolean = loaded

    external fun startTunnel(tunFd: Int, localIp: String, stunServer: String, keepaliveSec: Int): Int
    external fun stopTunnel()
    external fun discoverStunEndpoint(stunServer: String): String
    external fun setDefensePolicy(bunkerMode: Boolean, maxPps: Int)
    external fun getBlockedPacketsCount(): Long
    external fun inspectPacket(payloadLen: Int, dstPort: Int): Boolean

    // Data plane cifrado (X25519 ECDH + ChaCha20-Poly1305)
    external fun initSession(peerId: String, localKey: String, peerKey: String): Boolean
    external fun sealPacket(peerId: String, plaintext: ByteArray): ByteArray
    external fun openPacket(peerId: String, frame: ByteArray): ByteArray

    // Firma Ed25519 para challenge-response de señalización/relay
    external fun getSigningPublicKey(seed: String): String
    external fun signChallenge(seed: String, nonce: String): String
}
