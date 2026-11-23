import Network
import NetworkExtension
import NexoMeshCore   // XCFramework generado por scripts/build-ios.sh

/// Packet Tunnel Provider de NexoMesh (paridad con Android y Desktop):
/// - Conecta el flujo TUN real (`packetFlow`) al core `rust-core` (Noise IKpsk2 + DERP NM2).
/// - Configura Split DNS nativo (`NEDNSSettings`) para `.nexomesh` y `.mesh`.
/// - Ejecuta Socket Rebinding automático vía `NWPathMonitor` al cambiar Wi-Fi <-> 4G/5G.
class PacketTunnelProvider: NEPacketTunnelProvider {

    private var localIp: String = "10.0.0.2"
    private var peerIp: String = "10.0.0.1"
    private var mtu: NSNumber = 1280
    private var running = false
    private var pathMonitor: NWPathMonitor?
    private var lastPathStatus: NWPath.Status?

    override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        let cfg = (options as? [String: Any]) ?? [:]
        if let ip = cfg["virtualIp"] as? String { localIp = ip }
        if let pip = cfg["peerVirtualIp"] as? String { peerIp = pip }
        if let m = cfg["mtu"] as? Int { mtu = NSNumber(value: m) }

        // 1. Inicializar núcleo nativo y configurar sesión cifrada 1-RTT Noise IKpsk2
        nexomesh_init()
        let localKey = (cfg["localPrivateKey"] as? String) ?? "ios-local-key"
        let peerKey = (cfg["peerPublicKey"] as? String) ?? "peer-key"
        let endpoint = (cfg["peerEndpoint"] as? String) ?? ""
        let rc = nexomesh_configure_session(localIp, peerIp, localKey, peerKey, endpoint)
        if rc != 0 {
            completionHandler(NSError(
                domain: "io.nexomesh.vpn",
                code: Int(rc),
                userInfo: [NSLocalizedDescriptionKey: "nexomesh_configure_session falló"]
            ))
            return
        }

        // 2. Configurar interfaz TUN (10.0.0.0/24) + Split DNS nativo (*.nexomesh / *.mesh)
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: peerIp)
        settings.mtu = mtu
        let ipv4 = NEIPv4Settings(addresses: [localIp], subnetMasks: ["255.255.255.0"])
        ipv4.includedRoutes = [NEIPv4Route(destinationAddress: "10.0.0.0", subnetMask: "255.255.255.0")]
        settings.ipv4Settings = ipv4

        let dns = NEDNSSettings(servers: ["10.0.0.53"])
        dns.matchDomains = ["nexomesh", "mesh"]
        settings.dnsSettings = dns

        setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self = self else { completionHandler(error); return }
            if let error = error { completionHandler(error); return }

            self.running = true
            self.startPathMonitor()
            self.startTunOutboundLoop()
            self.startTunInboundLoop()
            completionHandler(nil)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        running = false
        pathMonitor?.cancel()
        pathMonitor = nil
        nexomesh_disconnect()
        completionHandler()
    }

    /// Escucha cambios de red física (Wi-Fi <-> celular) y ejecuta Socket Rebinding en rust-core.
    private func startPathMonitor() {
        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self = self, self.running else { return }
            if self.lastPathStatus != nil && path.status == .satisfied {
                let newPort = nexomesh_rebind_network()
                NSLog("[NexoMesh] NWPathMonitor cambio de red -> socket re-vinculado a puerto %d", newPort)
            }
            self.lastPathStatus = path.status
        }
        monitor.start(queue: DispatchQueue.global(qos: .utility))
        pathMonitor = monitor
    }

    /// TUN -> rust-core (cifra con Noise IKpsk2 y envía por UDP directo o relay DERP NM2).
    private func startTunOutboundLoop() {
        packetFlow.readPackets { [weak self] packets, _protocols in
            guard let self = self, self.running else { return }
            for data in packets {
                data.withUnsafeBytes { raw in
                    if let base = raw.bindMemory(to: UInt8.self).baseAddress {
                        _ = nexomesh_push_outbound_ip(base, Int32(data.count))
                    }
                }
            }
            if self.running {
                self.startTunOutboundLoop()
            }
        }
    }

    /// rust-core -> TUN (sondea UDP/DERP, ejecuta Disco + rekeying automático e inyecta IPv4).
    private func startTunInboundLoop() {
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            var buf = [UInt8](repeating: 0, count: 4096)
            let afInet = NSNumber(value: AF_INET)
            while let self = self, self.running {
                let n = nexomesh_poll_inbound_ip(&buf, Int32(buf.count))
                if n > 0 {
                    let pktData = Data(buf[0..<Int(n)])
                    self.packetFlow.writePackets([pktData], withProtocols: [afInet])
                } else {
                    Thread.sleep(forTimeInterval: 0.01)
                }
            }
        }
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        let json = String(cString: nexomesh_netcheck_json())
        completionHandler?(json.data(using: .utf8))
    }
}
