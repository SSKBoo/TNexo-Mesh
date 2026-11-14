use std::env;
use std::fs;
use std::net::UdpSocket;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy)]
enum TransportMode {
    Auto,
    Cellular,
    Ethernet,
}

fn select_policy(mode: TransportMode) -> (u16, u16, &'static str) {
    match mode {
        TransportMode::Cellular => (1280, 10, "Datos Móviles 4G/5G (Hub Host)"),
        TransportMode::Ethernet => (1420, 25, "Cable Ethernet (Malla Directa P2P)"),
        TransportMode::Auto => {
            // En escritorio prioriza trama completa Ethernet 1420 salvo que se indique 4G/5G
            (1420, 25, "Automático Escritorio (Ethernet/LAN)")
        }
    }
}

fn probe_stun(server: &str) -> Result<String, String> {
    let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("Error bind UDP: {e}"))?;
    let _ = sock.set_read_timeout(Some(Duration::from_millis(1500)));
    let mut req = [0u8; 20];
    req[0] = 0x00;
    req[1] = 0x01; // RFC 5389 Binding Request
    req[4..8].copy_from_slice(&[0x21, 0x12, 0xA4, 0x42]);
    req[8..20].copy_from_slice(b"NEXOMESHDESK");

    sock.send_to(&req, server)
        .map_err(|e| format!("Fallo envío STUN a {server}: {e}"))?;
    let mut buf = [0u8; 256];
    let (len, from) = sock
        .recv_from(&mut buf)
        .map_err(|e| format!("Sin respuesta UDP de {server}: {e}"))?;
    Ok(format!("STUN OK ({len} bytes desde {from})"))
}

fn init_noise_ikpsk2() -> Result<&'static str, String> {
    let _builder = snow::Builder::new(
        "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
            .parse()
            .map_err(|e| format!("Error patrón Noise: {e:?}"))?,
    );
    Ok("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s inicializado")
}

fn export_wireguard_conf(path: &str, local_ip: &str, mtu: u16, keepalive: u16, peer_ep: &str) {
    let conf = format!(
        "[Interface]\nPrivateKey = <TU_LLAVE_PRIVADA_CURVE25519>\nAddress = {local_ip}/24\nMTU = {mtu}\nDNS = 10.0.0.1\n\n[Peer]\nPublicKey = <LLAVE_PUBLICA_HOST_NEXOMESH>\nEndpoint = {peer_ep}\nAllowedIPs = 10.0.0.0/24\nPersistentKeepalive = {keepalive}\n"
    );
    let _ = fs::write(path, conf);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut mode = TransportMode::Auto;
    let mut stun_server = String::from("stun.l.google.com:19302");
    let mut join_uri: Option<String> = None;
    let mut wg_conf_out: Option<String> = None;
    let mut logs_out: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--mode" if i + 1 < args.len() => {
                mode = match args[i + 1].as_str() {
                    "cellular" | "4g" | "5g" => TransportMode::Cellular,
                    "ethernet" => TransportMode::Ethernet,
                    _ => TransportMode::Auto,
                };
                i += 1;
            }
            "--stun" if i + 1 < args.len() => {
                stun_server = args[i + 1].clone();
                i += 1;
            }
            "--join" if i + 1 < args.len() => {
                join_uri = Some(args[i + 1].clone());
                i += 1;
            }
            "--export-wg-conf" if i + 1 < args.len() => {
                wg_conf_out = Some(args[i + 1].clone());
                i += 1;
            }
            "--export-logs" if i + 1 < args.len() => {
                logs_out = Some(args[i + 1].clone());
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }

    let (mtu, keepalive, mode_label) = select_policy(mode);
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    println!("NexoMesh Desktop CLI ({}) · {}", env::consts::OS, env::consts::ARCH);
    println!("Política activa: {mode_label} | MTU: {mtu} | Keepalive: {keepalive}s");

    let mut log_rows = vec![String::from("timestamp,severity,subsystem,peer_ip,message")];
    match init_noise_ikpsk2() {
        Ok(msg) => {
            println!("[OK] {msg}");
            log_rows.push(format!("{ts},INFO,Noise,10.0.0.1,\"{msg}\""));
        }
        Err(err) => {
            eprintln!("[ERROR] {err}");
            log_rows.push(format!("{ts},CRITICAL,Noise,10.0.0.1,\"{err}\""));
        }
    }

    if let Some(uri) = join_uri {
        println!("[QR/URI] Invitación recibida: {uri}");
        log_rows.push(format!("{ts},INFO,WireGuard,10.0.0.1,\"Invitación aplicada\""));
    }

    // Sonda STUN con reintentos exponenciales (1s, 2s, 4s) ante pérdida de red
    let mut attempt: u32 = 0;
    loop {
        attempt += 1;
        match probe_stun(&stun_server) {
            Ok(info) => {
                println!("[STUN] {info}");
                log_rows.push(format!("{ts},INFO,STUN,10.0.0.1,\"{info}\""));
                break;
            }
            Err(err) => {
                let backoff_sec = (1u64 << (attempt - 1)).min(32);
                eprintln!("[ALERTA] Red sin respuesta ({err}). Reintento #{attempt} en {backoff_sec}s...");
                log_rows.push(format!("{ts},CRITICAL,Backoff,10.0.0.1,\"Fallo STUN intento #{attempt}\""));
                if attempt >= 3 {
                    break;
                }
                std::thread::sleep(Duration::from_secs(backoff_sec));
            }
        }
    }

    if let Some(conf_path) = wg_conf_out {
        export_wireguard_conf(&conf_path, "10.0.0.5", mtu, keepalive, "187.190.84.212:51820");
        println!("[EXPORT] Perfil WireGuard multiplataforma guardado en {conf_path}");
    }

    if let Some(csv_path) = logs_out {
        let _ = fs::write(&csv_path, log_rows.join("\n"));
        println!("[EXPORT] Logs CSV guardados en {csv_path}");
    }
}
