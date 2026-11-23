//! `netcheck` completo estilo Tailscale:
//! - STUN UDP simultáneo sobre IPv4 e IPv6
//! - Detección de variabilidad de mapeo de puertos (Symmetric NAT vs Cone NAT)
//! - Prueba de NAT Hairpinning sobre el endpoint STUN descubierto
//! - Medición de latencia HTTPS/TLS/TCP a nodos DERP
//! - Detección de portales cautivos (Wi-Fi de hoteles/aeropuertos vía redirecciones HTTP)

use crate::derp::{probe_derp_regions, select_nearest_derp_region, DerpRegion};
use crate::stun::{parse_mapped_address, stun_binding_request};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaptivePortalStatus {
    pub checked: bool,
    pub detected: bool,
    pub status_code: Option<u16>,
    pub location: Option<String>,
}

#[derive(Clone, Debug)]
pub struct FullNetcheckReport {
    pub udp_v4: bool,
    pub udp_v6: bool,
    pub global_v4: Option<String>,
    pub global_v6: Option<String>,
    pub mapping_varies_by_dest_ip: Option<bool>,
    pub hairpinning: Option<bool>,
    pub captive_portal: CaptivePortalStatus,
    pub preferred_derp: Option<u16>,
    pub derp_regions: Vec<DerpRegion>,
}

impl FullNetcheckReport {
    pub fn to_json(&self) -> String {
        let gv4 = self
            .global_v4
            .as_ref()
            .map(|s| format!("\"{s}\""))
            .unwrap_or_else(|| "null".into());
        let gv6 = self
            .global_v6
            .as_ref()
            .map(|s| format!("\"{s}\""))
            .unwrap_or_else(|| "null".into());
        let var = self
            .mapping_varies_by_dest_ip
            .map(|b| b.to_string())
            .unwrap_or_else(|| "null".into());
        let hair = self
            .hairpinning
            .map(|b| b.to_string())
            .unwrap_or_else(|| "null".into());
        let pderp = self
            .preferred_derp
            .map(|id| id.to_string())
            .unwrap_or_else(|| "null".into());
        let loc = self
            .captive_portal
            .location
            .as_ref()
            .map(|s| format!("\"{}\"", s.replace('"', "")))
            .unwrap_or_else(|| "null".into());
        let code = self
            .captive_portal
            .status_code
            .map(|c| c.to_string())
            .unwrap_or_else(|| "null".into());
        let derps: Vec<String> = self
            .derp_regions
            .iter()
            .map(|r| {
                format!(
                    "{{\"id\":{},\"name\":\"{}\",\"endpoint\":\"{}\",\"rtt_ms\":{}}}",
                    r.id, r.name, r.endpoint, r.rtt_ms
                )
            })
            .collect();
        format!(
            "{{\"udp_v4\":{},\"udp_v6\":{},\"global_v4\":{},\"global_v6\":{},\"mapping_varies_by_dest_ip\":{},\"hairpinning\":{},\"captive_portal\":{{\"checked\":{},\"detected\":{},\"status_code\":{},\"location\":{}}},\"preferred_derp\":{},\"derp_regions\":[{}]}}",
            self.udp_v4,
            self.udp_v6,
            gv4,
            gv6,
            var,
            hair,
            self.captive_portal.checked,
            self.captive_portal.detected,
            code,
            loc,
            pderp,
            derps.join(",")
        )
    }
}

fn stun_probe_on_socket(sock: &UdpSocket, target: SocketAddr) -> Option<String> {
    let req = stun_binding_request();
    sock.send_to(&req, target).ok()?;
    let mut buf = [0u8; 256];
    let (n, _) = sock.recv_from(&mut buf).ok()?;
    parse_mapped_address(&buf[..n])
}

/// Comprueba NAT Hairpinning enviando una sonda hacia nuestro propio endpoint público STUN.
pub fn test_hairpinning(sock: &UdpSocket, public_self: SocketAddr) -> bool {
    let tag = b"NM_HAIRPIN_PROBE_V1";
    if sock.send_to(tag, public_self).is_err() {
        return false;
    }
    let _ = sock.set_read_timeout(Some(Duration::from_millis(120)));
    let mut buf = [0u8; 128];
    for _ in 0..4 {
        if let Ok((n, _)) = sock.recv_from(&mut buf) {
            if &buf[..n] == tag {
                return true;
            }
        } else {
            break;
        }
    }
    false
}

/// Detecta portales cautivos consultando un endpoint HTTP (`host:port` + `path`) esperando `204`/`200` sin redirección `30x`.
pub fn detect_captive_portal(http_url: &str) -> CaptivePortalStatus {
    let stripped = http_url
        .trim()
        .strip_prefix("http://")
        .unwrap_or(http_url.trim());
    let (host_port, path) = match stripped.find('/') {
        Some(idx) => (&stripped[..idx], &stripped[idx..]),
        None => (stripped, "/generate_204"),
    };
    let host_only = host_port.split(':').next().unwrap_or(host_port);
    let addr_str = if host_port.contains(':') {
        host_port.to_string()
    } else {
        format!("{host_port}:80")
    };

    let Ok(mut addrs) = addr_str.to_socket_addrs() else {
        return CaptivePortalStatus {
            checked: false,
            detected: false,
            status_code: None,
            location: None,
        };
    };
    let Some(addr) = addrs.next() else {
        return CaptivePortalStatus {
            checked: false,
            detected: false,
            status_code: None,
            location: None,
        };
    };

    let Ok(mut tcp) = TcpStream::connect_timeout(&addr, Duration::from_millis(700)) else {
        return CaptivePortalStatus {
            checked: false,
            detected: false,
            status_code: None,
            location: None,
        };
    };
    let _ = tcp.set_read_timeout(Some(Duration::from_millis(700)));
    let req = format!("GET {path} HTTP/1.1\r\nHost: {host_only}\r\nConnection: close\r\n\r\n");
    if tcp.write_all(req.as_bytes()).is_err() {
        return CaptivePortalStatus {
            checked: false,
            detected: false,
            status_code: None,
            location: None,
        };
    }

    let mut resp = [0u8; 1024];
    let n = tcp.read(&mut resp).unwrap_or(0);
    if n == 0 {
        return CaptivePortalStatus {
            checked: false,
            detected: false,
            status_code: None,
            location: None,
        };
    }
    let text = String::from_utf8_lossy(&resp[..n]);
    let status_code = text
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok());
    let location = text
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("location:"))
        .map(|l| l.split_once(':').map(|x| x.1.trim().to_string()).unwrap_or_default());

    let redirected = matches!(status_code, Some(301 | 302 | 303 | 307 | 308));
    let detected = redirected || (status_code == Some(200) && text.contains("captive"));
    CaptivePortalStatus {
        checked: true,
        detected,
        status_code,
        location,
    }
}

/// Mide latencia real hacia regiones DERP (TLS/HTTPS si aplica en desktop, TCP RTT en cualquier target).
pub fn probe_derp_latencies(regions: &mut [DerpRegion]) {
    probe_derp_regions(regions);
    #[cfg(not(target_os = "android"))]
    {
        for r in regions.iter_mut() {
            if r.rtt_ms == u32::MAX || (!r.endpoint.starts_with("wss://") && !r.endpoint.starts_with("https://")) {
                continue;
            }
            if let Some(rest) = r
                .endpoint
                .strip_prefix("wss://")
                .or_else(|| r.endpoint.strip_prefix("https://"))
            {
                let host_port = rest.split('/').next().unwrap_or(rest);
                let host = host_port.split(':').next().unwrap_or(host_port);
                let port = host_port.split(':').nth(1).and_then(|p| p.parse().ok()).unwrap_or(443u16);
                if let Ok(mut addrs) = format!("{host}:{port}").to_socket_addrs() {
                    if let Some(addr) = addrs.next() {
                        let start = Instant::now();
                        if let Ok(tcp) = TcpStream::connect_timeout(&addr, Duration::from_millis(700)) {
                            let root_store = rustls::RootCertStore {
                                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
                            };
                            let cfg = rustls::ClientConfig::builder()
                                .with_root_certificates(root_store)
                                .with_no_client_auth();
                            if let Ok(name) = rustls::pki_types::ServerName::try_from(host.to_string()) {
                                if let Ok(conn) = rustls::ClientConnection::new(std::sync::Arc::new(cfg), name) {
                                    let mut tls = rustls::StreamOwned::new(conn, tcp);
                                    let _ = tls.conn.complete_io(&mut tls.sock);
                                    r.rtt_ms = start.elapsed().as_millis().min(u32::MAX as u128 - 1) as u32;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Ejecuta diagnóstico completo dual-stack + variabilidad NAT + hairpinning + DERP + portal cautivo.
pub fn run_full_netcheck(
    stun_primary_v4: &str,
    stun_secondary_v4: Option<&str>,
    stun_v6: Option<&str>,
    captive_url: Option<&str>,
    regions: &mut [DerpRegion],
) -> FullNetcheckReport {
    probe_derp_latencies(regions);
    let preferred_derp = select_nearest_derp_region(regions).map(|r| r.id);

    let mut global_v4 = None;
    let mut mapping_varies_by_dest_ip = None;
    let mut hairpinning = None;

    if let Ok(sock_v4) = UdpSocket::bind("0.0.0.0:0") {
        let _ = sock_v4.set_read_timeout(Some(Duration::from_millis(450)));
        if let Ok(mut a1) = stun_primary_v4.to_socket_addrs() {
            if let Some(addr1) = a1.find(|a| a.is_ipv4()) {
                global_v4 = stun_probe_on_socket(&sock_v4, addr1);
                if let Some(ref g1) = global_v4 {
                    if let Ok(self_pub) = g1.parse::<SocketAddr>() {
                        hairpinning = Some(test_hairpinning(&sock_v4, self_pub));
                    }
                    if let Some(sec) = stun_secondary_v4 {
                        if let Ok(mut a2) = sec.to_socket_addrs() {
                            if let Some(addr2) = a2.find(|a| a.is_ipv4()) {
                                if let Some(g2) = stun_probe_on_socket(&sock_v4, addr2) {
                                    let p1 = g1.rsplit_once(':').map(|x| x.1);
                                    let p2 = g2.rsplit_once(':').map(|x| x.1);
                                    mapping_varies_by_dest_ip = Some(p1 != p2);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let mut global_v6 = None;
    if let Some(v6_ep) = stun_v6 {
        if let Ok(sock_v6) = UdpSocket::bind("[::]:0") {
            let _ = sock_v6.set_read_timeout(Some(Duration::from_millis(450)));
            if let Ok(mut a6) = v6_ep.to_socket_addrs() {
                if let Some(addr6) = a6.find(|a| a.is_ipv6()) {
                    global_v6 = stun_probe_on_socket(&sock_v6, addr6);
                }
            }
        }
    }

    let captive_portal = match captive_url {
        Some(url) if !url.trim().is_empty() => detect_captive_portal(url),
        _ => CaptivePortalStatus {
            checked: false,
            detected: false,
            status_code: None,
            location: None,
        },
    };

    FullNetcheckReport {
        udp_v4: global_v4.is_some(),
        udp_v6: global_v6.is_some(),
        global_v4,
        global_v6,
        mapping_varies_by_dest_ip,
        hairpinning,
        captive_portal,
        preferred_derp,
        derp_regions: regions.to_vec(),
    }
}
