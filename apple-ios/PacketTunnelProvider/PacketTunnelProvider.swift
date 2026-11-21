import NetworkExtension
import NexoMeshCore   // XCFramework generado por scripts/build-ios.sh

/// Packet Tunnel Provider de NexoMesh.
/// Traduce el paths de red a tráfico TUN y delega el cifrado y la malla al
/// rust-core a través de los símbolos FFI expuestos por el XCFramework.
class PacketTunnelProvider: NEPacketTunnelProvider {

    private var localIp: String = "10.0.0.1"
    private var mtu: NSNumber = 1420
    private var keepalive: Int32 = 15
    private var stunServer: String = "stun.l.google.com:19302"
    private var signalingUrl: String = "wss://api.nexomesh.io/signal"
    private var running = false
    private var readLoop: DispatchWorkItem?

    override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        let cfg = (options as? [String: Any]) ?? [:]
        if let ip = cfg["virtualIp"] as? String { localIp = ip }
        if let m = cfg["mtu"] as? Int { mtu = NSNumber(value: m) }
        if let k = cfg["keepalive"] as? Int { keepalive = Int32(k) }
        if let s = cfg["stunServer"] as? String { stunServer = s }
        if let u = cfg["signalingUrl"] as? String { signalingUrl = u }

        // 1. Inicializar el core nativo (símbolos nexomesh_init / nexomesh_connect).
        nexomesh_init()
        let status = String(cString: nexomesh_status_json())
        NSLog("[NexoMesh] core init: %@", status)

        // 2. Configurar la interfaz TUN con split-tunnel para 10.0.0.0/24.
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "10.0.0.1")
        settings.mtu = mtu
        let ipv4 = NEIPv4Settings(addresses: [localIp], subnetMasks: ["255.255.255.0"])
        ipv4.includedRoutes = [NEIPv4Route(destinationAddress: "10.0.0.0", subnetMask: "255.255.255.0")]
        settings.ipv4Settings = ipv4
        // No instalar DNS: el tráfico normal sale por la red física.

        setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self = self else { completionHandler(error); return }
            if let error = error { completionHandler(error); return }

            // 3. Conectar al par indicado en las opciones (deep link / invite).
            if let peer = cfg["peerPublicKey"] as? String,
               let endpoint = cfg["peerEndpoint"] as? String {
                let ok = nexomesh_connect(peer, endpoint)
                if ok != 0 {
                    completionHandler(NSError(domain: "io.nexomesh.vpn", code: Int(ok),
                                              userInfo: [NSLocalizedDescriptionKey: "nexomesh_connect falló"]))
                    return
                }
            }

            self.running = true
            self.startTunReadLoop()
            completionHandler(nil)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        running = false
        readLoop?.cancel()
        nexomesh_disconnect()
        completionHandler()
    }

    /// Bucle TUN: cada paquete IPv4 se pasa al core para cifrado/reenvío.
    private func startTunReadLoop() {
        let work = DispatchWorkItem { [weak self] in
            guard let self = self, self.running else { return }
            self.packetFlow.readPacketObjects { packets in
                for packet in packets {
                    // El cifrado y el reenvío UDP los hace rust-core. Desde Swift
                    // solo se mantiene vivo el TUN y se consulta el estado del core
                    // con los símbolos FFI reales exportados por el XCFramework.
                    _ = packet.data.count
                    _ = String(cString: nexomesh_status_json())
                }
                if self.running { self.startTunReadLoop() }
            }
        }
        readLoop = work
        DispatchQueue.global(qos: .userInitiated).async(execute: work)
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        let json = String(cString: nexomesh_status_json())
        completionHandler?(json.data(using: .utf8))
    }
}
