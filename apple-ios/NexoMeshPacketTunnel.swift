import NetworkExtension

final class NexoMeshPacketTunnelProvider: NEPacketTunnelProvider {
    override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "187.190.84.212")
        let ipv4 = NEIPv4Settings(addresses: ["10.0.0.3"], subnetMasks: ["255.255.255.0"])
        ipv4.includedRoutes = [NEIPv4Route(destinationAddress: "10.0.0.0", subnetMask: "255.255.255.0")]
        settings.ipv4Settings = ipv4
        settings.mtu = NSNumber(value: 1280)
        settings.dnsSettings = NEDNSSettings(servers: ["10.0.0.1"])

        setTunnelNetworkSettings(settings) { error in
            completionHandler(error)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        completionHandler()
    }
}
