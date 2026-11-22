use std::env;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

mod gui;
#[cfg(target_os = "windows")]
mod win_tun;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod unix_tun;

#[derive(Clone, Copy)]
enum TransportMode {
    Auto,
    Cellular,
    Wifi,
    Ethernet,
}

fn select_policy(mode: TransportMode) -> (u16, u16, &'static str) {
    match mode {
        TransportMode::Cellular => (1280, 10, "Datos Móviles 4G/5G (Hub Host)"),
        TransportMode::Wifi => (1380, 15, "Red Wi-Fi (Enlace Directo UDP)"),
        TransportMode::Ethernet => (1420, 25, "Cable Ethernet (Malla Directa P2P)"),
        TransportMode::Auto => (1420, 25, "Automático Escritorio (Ethernet/LAN)"),
    }
}

pub fn probe_stun(server: &str) -> Result<String, String> {
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
    // Split-tunnel: sin sobreescribir DNS para mantener navegación normal a internet
    let conf = format!(
        "[Interface]\nPrivateKey = <TU_LLAVE_PRIVADA_CURVE25519>\nAddress = {local_ip}/24\nMTU = {mtu}\n\n[Peer]\nPublicKey = <LLAVE_PUBLICA_HOST_NEXOMESH>\nEndpoint = {peer_ep}\nAllowedIPs = 10.0.0.0/24\nPersistentKeepalive = {keepalive}\n"
    );
    let _ = fs::write(path, conf);
}

pub fn send_bytes_p2p(name: &str, data: &[u8], target_ip: &str) -> Result<String, String> {
    let addr = if target_ip.contains(':') {
        target_ip.to_string()
    } else {
        format!("{target_ip}:51821")
    };
    let mut stream = TcpStream::connect(&addr).map_err(|e| format!("Error conectando a {addr}: {e}"))?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let header = format!("NEXOMESH_FILE\n{name}\n{}\n", data.len());
    stream.write_all(header.as_bytes()).map_err(|e| format!("Error enviando cabecera: {e}"))?;
    stream.write_all(data).map_err(|e| format!("Error enviando bytes: {e}"))?;
    stream.flush().map_err(|e| format!("Error flush: {e}"))?;
    let mut ack_buf = [0u8; 256];
    let ack = match stream.read(&mut ack_buf) {
        Ok(n) if n > 0 => String::from_utf8_lossy(&ack_buf[..n]).trim().to_string(),
        _ => String::new(),
    };
    let msg = if ack.starts_with("NEXOMESH_ACK|OK") {
        format!("'{name}' ({} bytes) confirmado por {addr}", data.len())
    } else {
        format!("'{name}' ({} bytes) enviado a {addr}", data.len())
    };
    println!("[ARCHIVO] {msg}");
    Ok(msg)
}

fn send_file_p2p(file_path: &str, target_ip: &str) -> Result<(), String> {
    let data = fs::read(file_path).map_err(|e| format!("Error leyendo {file_path}: {e}"))?;
    let name = Path::new(file_path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("archivo.bin");
    send_bytes_p2p(name, &data, target_ip)?;
    Ok(())
}

pub fn handle_incoming_file_conn(mut stream: TcpStream, save_dir: &Path) -> Option<(String, u64)> {
    let mut reader = BufReader::new(stream.try_clone().ok()?);
    let mut magic = String::new();
    let mut name = String::new();
    let mut size_str = String::new();
    if reader.read_line(&mut magic).is_ok()
        && magic.trim() == "NEXOMESH_FILE"
        && reader.read_line(&mut name).is_ok()
        && reader.read_line(&mut size_str).is_ok()
    {
        let clean_name = Path::new(name.trim())
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("recibido.bin")
            .to_string();
        let size: u64 = size_str.trim().parse().unwrap_or(0);
        let max_bytes: u64 = std::env::var("NEXOMESH_MAX_FILE_BYTES")
            .ok().and_then(|v| v.parse().ok()).unwrap_or(2 * 1024 * 1024 * 1024);
        if size > max_bytes {
            eprintln!("[RECEPTOR] Rechazado '{clean_name}': {size} bytes > limite {max_bytes}");
            return None;
        }
        let target_path = save_dir.join(&clean_name);
        match fs::File::create(&target_path) {
            Ok(mut out) => {
                let mut buf = [0u8; 65_536];
                let mut remaining = size;
                let mut ok = true;
                while remaining > 0 {
                    let want = remaining.min(buf.len() as u64) as usize;
                    match reader.read(&mut buf[..want]) {
                        Ok(0) => { ok = false; break; }
                        Ok(n) => { if out.write_all(&buf[..n]).is_err() { ok = false; break; } remaining -= n as u64; }
                        Err(_) => { ok = false; break; }
                    }
                }
                if ok {
                    let _ = stream.write_all(format!("NEXOMESH_ACK|OK|{size}|desktop\n").as_bytes());
                    let _ = stream.flush();
                    println!("[RECEPTOR] Guardado '{}' ({size} bytes)", target_path.display());
                    return Some((clean_name, size));
                } else {
                    eprintln!("[RECEPTOR] Transferencia incompleta de '{clean_name}'");
                }
            }
            Err(e) => eprintln!("[RECEPTOR] No se pudo crear '{}': {e}", target_path.display()),
        }
    }
    None
}

fn receive_files_p2p() -> Result<(), String> {
    let listener = TcpListener::bind("0.0.0.0:51821").map_err(|e| format!("Error puerto 51821: {e}"))?;
    let save_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    println!("[RECEPTOR] Escuchando archivos P2P en TCP :51821...");
    for stream in listener.incoming().flatten() {
        let _ = handle_incoming_file_conn(stream, &save_dir);
    }
    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() == 1 || args.iter().any(|a| a == "--gui") {
        gui::run_gui();
        return;
    }
    let mut mode = TransportMode::Auto;
    let mut stun_server = String::from("stun.l.google.com:19302");
    let mut join_uri: Option<String> = None;
    let mut wg_conf_out: Option<String> = None;
    let mut logs_out: Option<String> = None;
    let mut send_file: Option<String> = None;
    let mut send_to = String::from("10.0.0.2");
    let mut receive_mode = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--mode" if i + 1 < args.len() => {
                mode = match args[i + 1].as_str() {
                    "cellular" | "4g" | "5g" => TransportMode::Cellular,
                    "wifi" | "wi-fi" => TransportMode::Wifi,
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
            "--send-file" if i + 1 < args.len() => {
                send_file = Some(args[i + 1].clone());
                i += 1;
            }
            "--to" if i + 1 < args.len() => {
                send_to = args[i + 1].clone();
                i += 1;
            }
            "--receive-files" => {
                receive_mode = true;
            }
            _ => {}
        }
        i += 1;
    }

    if let Some(path) = send_file {
        if let Err(err) = send_file_p2p(&path, &send_to) {
            eprintln!("[ERROR ARCHIVO] {err}");
        }
        return;
    }

    if receive_mode {
        if let Err(err) = receive_files_p2p() {
            eprintln!("[ERROR RECEPTOR] {err}");
        }
        return;
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
        let peer_ep = std::env::var("NEXOMESH_PEER_ENDPOINT")
            .unwrap_or_else(|_| "127.0.0.1:51820".to_string());
        export_wireguard_conf(&conf_path, "10.0.0.5", mtu, keepalive, &peer_ep);
        println!("[EXPORT] Perfil WireGuard multiplataforma guardado en {conf_path}");
    }

    if let Some(csv_path) = logs_out {
        let _ = fs::write(&csv_path, log_rows.join("\n"));
        println!("[EXPORT] Logs CSV guardados en {csv_path}");
    }
}
