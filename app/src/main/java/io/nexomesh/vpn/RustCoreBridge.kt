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

    // MagicDNS local (.mesh / .nexomesh) + Motor ACL por nodo
    external fun registerMagicDnsHost(name: String, ipv4: String)
    external fun resolveMagicDnsPacket(query: ByteArray): ByteArray
    external fun addAclRule(allow: Boolean, srcCidr: String, dstCidr: String, ipProto: Int, dstPort: Int)
    external fun checkAclPacket(srcIp: String, dstIp: String, ipProto: Int, dstPort: Int): Boolean

    // Rotación PFS efímera automática + handshake 1-RTT Noise IKpsk2
    external fun needsRekey(peerId: String): Boolean
    external fun beginPfsRekey(peerId: String): ByteArray
    external fun finishPfsRekey(peerId: String, peerEphPub: ByteArray): Boolean
    external fun beginNoiseIkHandshake(peerId: String): ByteArray
    external fun respondNoiseIkHandshake(peerId: String, msg1: ByteArray): ByteArray
    external fun completeNoiseIkHandshake(peerId: String, msg2: ByteArray): Boolean
    external fun isNoiseIkEstablished(peerId: String): Boolean
}
