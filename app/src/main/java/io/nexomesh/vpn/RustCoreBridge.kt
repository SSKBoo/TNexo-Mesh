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
}
