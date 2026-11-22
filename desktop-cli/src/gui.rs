use nexomesh_core::crypto::generate_keypair;
use nexomesh_core::derp::{
    build_icmp_echo_request, try_build_icmp_echo_reply, Node, NodeEvent,
};
use nexomesh_core::keys::{sign_challenge_b64, signing_public_key_b64};
use nexomesh_core::session;
use nexomesh_core::ws_client::{
    base64_decode, base64_encode, extract_json_str, WsClient, WsFrame,
};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::{handle_incoming_file_conn, probe_stun, send_bytes_p2p};

struct GuiState {
    receiver_active: bool,
    tunnel_active: bool,
    relay_connected: bool,
    direct_udp: bool,
    local_vip: String,
    peer_vip: String,
    local_key: String,
    peer_key: String,
    relay_url: String,
    peer_endpoint: String,
    last_stun: String,
    events: Vec<String>,
    save_dir: PathBuf,
    outbound_packets: Vec<Vec<u8>>,
    ping_sent_at: Option<(u16, Instant)>,
    ping_seq: u16,
}

fn load_or_create_key(cfg_path: &Path) -> String {
    if let Ok(content) = fs::read_to_string(cfg_path) {
        let trimmed = content.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    let (_, pk) = generate_keypair();
    let b64 = base64_encode(pk.as_bytes());
    let _ = fs::write(cfg_path, &b64);
    b64
}

fn detect_lan_ip() -> String {
    if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
        if sock.connect("8.8.8.8:80").is_ok() {
            if let Ok(addr) = sock.local_addr() {
                return addr.ip().to_string();
            }
        }
    }
    "127.0.0.1".to_string()
}

fn open_browser(url: &str) {
    #[cfg(target_os = "windows")]
    let _ = Command::new("cmd").args(["/c", "start", "", url]).spawn();
    #[cfg(target_os = "macos")]
    let _ = Command::new("open").arg(url).spawn();
    #[cfg(target_os = "linux")]
    let _ = Command::new("xdg-open").arg(url).spawn();
}

fn open_folder_in_os(dir: &Path) {
    #[cfg(target_os = "windows")]
    let _ = Command::new("explorer").arg(dir).spawn();
    #[cfg(target_os = "macos")]
    let _ = Command::new("open").arg(dir).spawn();
    #[cfg(target_os = "linux")]
    let _ = Command::new("xdg-open").arg(dir).spawn();
}

pub fn run_gui() {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let save_dir = cwd.join("NexoMesh_Recibidos");
    let _ = fs::create_dir_all(&save_dir);
    let local_key = load_or_create_key(&cwd.join("nexomesh_pc.key"));

    let state = Arc::new(Mutex::new(GuiState {
        receiver_active: false,
        tunnel_active: false,
        relay_connected: false,
        direct_udp: false,
        local_vip: "10.0.0.2".to_string(),
        peer_vip: "10.0.0.1".to_string(),
        local_key,
        peer_key: String::new(),
        relay_url: String::new(),
        peer_endpoint: String::new(),
        last_stun: String::new(),
        events: vec![format!("📂 Carpeta: {}", save_dir.display())],
        save_dir,
        outbound_packets: Vec::new(),
        ping_sent_at: None,
        ping_seq: 0,
    }));

    let listener = TcpListener::bind("127.0.0.1:51822")
        .or_else(|_| TcpListener::bind("127.0.0.1:0"))
        .expect("No se pudo abrir servidor GUI local");
    let port = listener.local_addr().map(|a| a.port()).unwrap_or(51822);
    let url = format!("http://127.0.0.1:{port}");
    println!("NexoMesh Desktop UI -> {url}");
    open_browser(&url);

    for stream in listener.incoming().flatten() {
        let st = Arc::clone(&state);
        thread::spawn(move || handle_http(stream, st));
    }
}

fn handle_http(mut stream: TcpStream, state: Arc<Mutex<GuiState>>) {
    let mut reader = BufReader::new(match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    });
    let mut req_line = String::new();
    if reader.read_line(&mut req_line).is_err() || req_line.is_empty() {
        return;
    }
    let parts: Vec<&str> = req_line.split_whitespace().collect();
    if parts.len() < 2 {
        return;
    }
    let method = parts[0];
    let full_path = parts[1];
    let mut content_len: usize = 0;
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h).is_err() || h == "\r\n" || h.is_empty() {
            break;
        }
        let lower = h.to_ascii_lowercase();
        if let Some(val) = lower.strip_prefix("content-length:") {
            content_len = val.trim().parse().unwrap_or(0);
        }
    }

    let (path, query) = match full_path.split_once('?') {
        Some((p, q)) => (p, q),
        None => (full_path, ""),
    };

    match (method, path) {
        ("GET", "/") => {
            write_http(&mut stream, "200 OK", "text/html; charset=utf-8", HTML_UI.as_bytes());
        }
        ("GET", "/api/status") => {
            let lan = detect_lan_ip();
            let g = state.lock().unwrap();
            let sign_pub = signing_public_key_b64(&g.local_key);
            let events_json = g
                .events
                .iter()
                .take(40)
                .map(|e| format!("\"{}\"", escape_json(e)))
                .collect::<Vec<_>>()
                .join(",");
            let json = format!(
                "{{\"lanIp\":\"{}\",\"localVip\":\"{}\",\"peerVip\":\"{}\",\"localKey\":\"{}\",\"signingPub\":\"{}\",\"relayUrl\":\"{}\",\"peerEndpoint\":\"{}\",\"lastStun\":\"{}\",\"receiverActive\":{},\"tunnelActive\":{},\"relayConnected\":{},\"directUdp\":{},\"events\":[{}]}}",
                escape_json(&lan),
                escape_json(&g.local_vip),
                escape_json(&g.peer_vip),
                escape_json(&g.local_key),
                escape_json(&sign_pub),
                escape_json(&g.relay_url),
                escape_json(&g.peer_endpoint),
                escape_json(&g.last_stun),
                g.receiver_active,
                g.tunnel_active,
                g.relay_connected,
                g.direct_udp,
                events_json
            );
            write_http(&mut stream, "200 OK", "application/json", json.as_bytes());
        }
        ("POST", "/api/receiver/start") => {
            let mut g = state.lock().unwrap();
            if !g.receiver_active {
                g.receiver_active = true;
                let dir = g.save_dir.clone();
                let st_bg = Arc::clone(&state);
                g.events.insert(0, "📥 Receptor TCP :51821 activado".to_string());
                drop(g);
                thread::spawn(move || {
                    if let Ok(rx_listener) = TcpListener::bind("0.0.0.0:51821") {
                        for conn in rx_listener.incoming().flatten() {
                            if let Some((fname, size)) = handle_incoming_file_conn(conn, &dir) {
                                let mut guard = st_bg.lock().unwrap();
                                guard.events.insert(0, format!("📥 Recibido '{fname}' ({size} B)"));
                            }
                        }
                    } else {
                        let mut guard = st_bg.lock().unwrap();
                        guard.receiver_active = false;
                        guard.events.insert(0, "❌ Puerto :51821 ocupado".to_string());
                    }
                });
            }
            write_http(&mut stream, "200 OK", "application/json", b"{\"ok\":true}");
        }
        ("POST", "/api/open-folder") => {
            let dir = state.lock().unwrap().save_dir.clone();
            open_folder_in_os(&dir);
            write_http(&mut stream, "200 OK", "application/json", b"{\"ok\":true}");
        }
        ("GET", "/api/stun") => {
            let res = probe_stun("stun.l.google.com:19302").unwrap_or_else(|e| e);
            if let Some(ep) = res.split("desde ").nth(1) {
                state.lock().unwrap().last_stun = ep.trim_end_matches(')').to_string();
            }
            state.lock().unwrap().events.insert(0, format!("🌐 {res}"));
            let json = format!("{{\"result\":\"{}\"}}", escape_json(&res));
            write_http(&mut stream, "200 OK", "application/json", json.as_bytes());
        }
        ("POST", "/api/join") => {
            let uri_str = read_body_string(&mut reader, content_len);
            let msg = apply_join_uri(&uri_str, &state);
            let json = format!("{{\"ok\":true,\"message\":\"{}\"}}", escape_json(&msg));
            write_http(&mut stream, "200 OK", "application/json", json.as_bytes());
        }
        ("POST", "/api/tunnel/start") => {
            let body = read_body_string(&mut reader, content_len);
            {
                let mut g = state.lock().unwrap();
                if let Some(r) = extract_json_str(&body, "relayUrl") {
                    g.relay_url = r;
                }
                if let Some(lv) = extract_json_str(&body, "localVip") {
                    if !lv.is_empty() { g.local_vip = lv; }
                }
                if let Some(pv) = extract_json_str(&body, "peerVip") {
                    if !pv.is_empty() { g.peer_vip = pv; }
                }
                if let Some(pk) = extract_json_str(&body, "peerKey") {
                    if !pk.is_empty() { g.peer_key = pk; }
                }
                if let Some(ep) = extract_json_str(&body, "peerEndpoint") {
                    g.peer_endpoint = ep;
                }
                if !g.tunnel_active {
                    g.tunnel_active = true;
                    let st_bg = Arc::clone(&state);
                    thread::spawn(move || run_tunnel_loop(st_bg));
                }
            }
            write_http(&mut stream, "200 OK", "application/json", b"{\"ok\":true}");
        }
        ("POST", "/api/ping") => {
            let mut g = state.lock().unwrap();
            if !g.tunnel_active {
                write_http(&mut stream, "400 Bad Request", "application/json", b"{\"ok\":false,\"error\":\"Conecta primero el tunel\"}");
                return;
            }
            g.ping_seq = g.ping_seq.wrapping_add(1);
            let seq = g.ping_seq;
            if let Ok(pkt) = build_icmp_echo_request(&g.local_vip, &g.peer_vip, seq) {
                let pv = g.peer_vip.clone();
                g.ping_sent_at = Some((seq, Instant::now()));
                g.outbound_packets.push(pkt);
                g.events.insert(0, format!("📡 Ping #{seq} -> {pv}"));
            }
            write_http(&mut stream, "200 OK", "application/json", b"{\"ok\":true}");
        }
        ("GET", "/api/invite") => {
            let g = state.lock().unwrap();
            let lan = detect_lan_ip();
            let ep = if g.last_stun.contains(':') {
                g.last_stun.clone()
            } else {
                format!("{lan}:51820")
            };
            let mut uri = format!(
                "nexomesh://join?pk={}&ep={}&lan={}:51820&hostIp={}&ip=10.0.0.3&noise=IKpsk2&name=NexoMesh-PC&auth2fa=0",
                url_encode(&g.local_key),
                url_encode(&ep),
                url_encode(&lan),
                url_encode(&g.local_vip)
            );
            if !g.relay_url.is_empty() {
                uri.push_str("&relay=");
                uri.push_str(&url_encode(&g.relay_url));
            }
            let json = format!("{{\"uri\":\"{}\"}}", escape_json(&uri));
            write_http(&mut stream, "200 OK", "application/json", json.as_bytes());
        }
        ("POST", "/api/send") => {
            let mut to = String::new();
            let mut name = String::from("archivo.bin");
            for pair in query.split('&') {
                if let Some((k, v)) = pair.split_once('=') {
                    if k == "to" {
                        to = url_decode(v);
                    } else if k == "name" {
                        name = url_decode(v);
                    }
                }
            }
            let max_upload = 16 * 1024 * 1024;
            if content_len == 0 || content_len > max_upload {
                write_http(&mut stream, "400 Bad Request", "application/json", b"{\"ok\":false,\"error\":\"tamano invalido (max 16MB)\"}");
                return;
            }
            let mut body = vec![0u8; content_len];
            if reader.read_exact(&mut body).is_err() {
                write_http(&mut stream, "400 Bad Request", "application/json", b"{\"ok\":false,\"error\":\"lectura incompleta\"}");
                return;
            }
            let target = if to.is_empty() {
                state.lock().unwrap().peer_vip.clone()
            } else {
                to
            };
            match send_bytes_p2p(&name, &body, &target) {
                Ok(msg) => {
                    state.lock().unwrap().events.insert(0, format!("📤 LAN/TCP: {msg}"));
                    let json = format!("{{\"ok\":true,\"message\":\"{}\"}}", escape_json(&msg));
                    write_http(&mut stream, "200 OK", "application/json", json.as_bytes());
                }
                Err(lan_err) => {
                    // Fallback tipo Tailscale: enviar cifrado dentro de frame NM1 por Relay/UDP
                    let mut g = state.lock().unwrap();
                    if g.tunnel_active && (g.relay_connected || g.direct_udp) {
                        let mut payload = format!("NM_F|{name}\n").into_bytes();
                        payload.extend_from_slice(&body);
                        g.outbound_packets.push(payload);
                        let msg = format!("'{name}' ({} B) enviado cifrado vía Túnel/Relay", body.len());
                        g.events.insert(0, format!("📤 {msg}"));
                        let json = format!("{{\"ok\":true,\"message\":\"{}\"}}", escape_json(&msg));
                        write_http(&mut stream, "200 OK", "application/json", json.as_bytes());
                    } else {
                        g.events.insert(0, format!("💔 Error envío: {lan_err}"));
                        let json = format!("{{\"ok\":false,\"error\":\"{}\"}}", escape_json(&lan_err));
                        write_http(&mut stream, "500 Internal Server Error", "application/json", json.as_bytes());
                    }
                }
            }
        }
        _ => write_http(&mut stream, "404 Not Found", "text/plain", b"not found"),
    }
}

fn read_body_string(reader: &mut BufReader<TcpStream>, len: usize) -> String {
    let mut buf = vec![0u8; len.min(65536)];
    if buf.is_empty() {
        return String::new();
    }
    if reader.read_exact(&mut buf).is_ok() {
        String::from_utf8_lossy(&buf).into_owned()
    } else {
        String::new()
    }
}

fn apply_join_uri(raw: &str, state: &Arc<Mutex<GuiState>>) -> String {
    let query = raw.split_once('?').map(|(_, q)| q).unwrap_or(raw);
    let mut g = state.lock().unwrap();
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            let val = url_decode(v);
            match k {
                "pk" => g.peer_key = val,
                "hostIp" => g.peer_vip = val,
                "ip" => g.local_vip = val,
                "ep" | "lan" if !val.is_empty() && !val.contains("auto") => g.peer_endpoint = val,
                "relay" => g.relay_url = val,
                _ => {}
            }
        }
    }
    let msg = format!("Par {} ({}) cargado", g.peer_vip, if g.relay_url.is_empty() { "UDP" } else { &g.relay_url });
    g.events.insert(0, format!("🔗 {msg}"));
    msg
}

fn run_tunnel_loop(state: Arc<Mutex<GuiState>>) {
    let (local_vip, peer_vip, local_key, peer_key, relay_url, peer_ep) = {
        let g = state.lock().unwrap();
        (
            g.local_vip.clone(),
            g.peer_vip.clone(),
            g.local_key.clone(),
            g.peer_key.clone(),
            g.relay_url.clone(),
            g.peer_endpoint.clone(),
        )
    };
    let effective_peer_key = if peer_key.is_empty() {
        format!("peer-{peer_vip}")
    } else {
        peer_key
    };
    if let Err(e) = session::ensure_session(&peer_vip, &local_key, &effective_peer_key) {
        let mut g = state.lock().unwrap();
        g.events.insert(0, format!("❌ Sesión cripto: {e}"));
        g.tunnel_active = false;
        return;
    }

    let mut node = match Node::bind(&local_vip, &peer_vip, 51820).or_else(|_| Node::bind(&local_vip, &peer_vip, 0)) {
        Ok(n) => n,
        Err(e) => {
            let mut g = state.lock().unwrap();
            g.events.insert(0, format!("❌ Bind UDP: {e}"));
            g.tunnel_active = false;
            return;
        }
    };
    if let Ok(addr) = peer_ep.parse::<SocketAddr>() {
        node.set_peer(addr);
    }

    let relay_rx = if !relay_url.is_empty() {
        Some(node.enable_relay())
    } else {
        None
    };

    let mut ws: Option<WsClient> = if !relay_url.is_empty() {
        match WsClient::connect(&relay_url) {
            Ok(mut client) => {
                let mut reg_id = format!("pc-{local_vip}");
                let mut sig = String::new();
                if let Ok(Some(WsFrame::Text(first))) = client.recv_frame() {
                    if extract_json_str(&first, "type").as_deref() == Some("challenge") {
                        if let Some(nonce) = extract_json_str(&first, "nonce") {
                            let (pub_b64, sig_b64) = sign_challenge_b64(&local_key, &nonce);
                            reg_id = pub_b64;
                            sig = sig_b64;
                        }
                    }
                }
                let reg = if sig.is_empty() {
                    format!(r#"{{"type":"register","from":"{reg_id}"}}"#)
                } else {
                    format!(r#"{{"type":"register","from":"{reg_id}","signature":"{sig}"}}"#)
                };
                if client.send_text(&reg).is_ok() {
                    let mut g = state.lock().unwrap();
                    g.relay_connected = true;
                    g.events.insert(0, format!("✅ Relay conectado: {relay_url}"));
                    Some(client)
                } else {
                    None
                }
            }
            Err(e) => {
                state.lock().unwrap().events.insert(0, format!("❌ Relay error: {e}"));
                None
            }
        }
    } else {
        None
    };

    let mut last_hello = Instant::now() - Duration::from_secs(10);
    let mut last_hb = Instant::now();
    loop {
        if !state.lock().unwrap().tunnel_active {
            break;
        }
        if last_hello.elapsed() >= Duration::from_secs(5) {
            let _ = node.send_hello("NexoMesh-PC");
            last_hello = Instant::now();
        }
        if let Some(client) = ws.as_mut() {
            if last_hb.elapsed() >= Duration::from_secs(20) {
                let _ = client.send_text(r#"{"type":"heartbeat"}"#);
                last_hb = Instant::now();
            }
        }

        // Enviar paquetes encolados desde la GUI (Ping o archivos NM_F|)
        let pending: Vec<Vec<u8>> = {
            let mut g = state.lock().unwrap();
            std::mem::take(&mut g.outbound_packets)
        };
        for pkt in pending {
            let _ = node.send_packet(&pkt);
        }

        if let (Some(rx), Some(client)) = (relay_rx.as_ref(), ws.as_mut()) {
            while let Ok(frame) = rx.try_recv() {
                if client.send_binary(&frame).is_err() {
                    state.lock().unwrap().relay_connected = false;
                    break;
                }
            }
        }

        if let Ok(Some(ev)) = node.poll_udp_once() {
            match ev {
                NodeEvent::Hello { vip, .. } | NodeEvent::Ack { vip, .. } => {
                    let mut g = state.lock().unwrap();
                    if !g.direct_udp {
                        g.direct_udp = true;
                        g.events.insert(0, format!("⚡ UDP directo confirmado con {vip}"));
                    }
                }
                NodeEvent::Packet { sender_vip, packet } => {
                    handle_tunnel_payload(&node, &local_vip, &sender_vip, &packet, "UDP", &state);
                }
            }
        }

        if let Some(client) = ws.as_mut() {
            match client.recv_frame() {
                Ok(Some(WsFrame::Text(txt))) => {
                    if extract_json_str(&txt, "type").as_deref() == Some("relay") {
                        if let Some(b64) = extract_json_str(&txt, "data") {
                            if let Ok(frame) = base64_decode(&b64) {
                                if let Ok((svip, pkt)) = Node::parse_nm1_frame(&frame) {
                                    handle_tunnel_payload(&node, &local_vip, &svip, &pkt, "RELAY", &state);
                                }
                            }
                        }
                    }
                }
                Ok(Some(WsFrame::Binary(frame))) => {
                    if let Ok((svip, pkt)) = Node::parse_nm1_frame(&frame) {
                        handle_tunnel_payload(&node, &local_vip, &svip, &pkt, "RELAY", &state);
                    }
                }
                Ok(Some(WsFrame::Closed)) | Err(_) => {
                    state.lock().unwrap().relay_connected = false;
                    ws = None;
                }
                Ok(None) => {}
            }
        }
    }
}

fn handle_tunnel_payload(
    node: &Node,
    local_vip: &str,
    sender_vip: &str,
    packet: &[u8],
    via: &str,
    state: &Arc<Mutex<GuiState>>,
) {
    if packet.starts_with(b"NM_F|") {
        if let Some(nl) = packet[5..].iter().position(|&b| b == b'\n') {
            let raw_name = String::from_utf8_lossy(&packet[5..5 + nl]);
            let clean = Path::new(raw_name.as_ref())
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("recibido.bin")
                .to_string();
            let data = &packet[5 + nl + 1..];
            let dir = state.lock().unwrap().save_dir.clone();
            if fs::write(dir.join(&clean), data).is_ok() {
                state.lock().unwrap().events.insert(0, format!("📥 [{via}] Recibido '{clean}' ({} B)", data.len()));
            }
        }
        return;
    }

    // ICMP Echo Reply
    if packet.len() >= 28 && (packet[0] >> 4) == 4 && packet[9] == 1 {
        let ihl = ((packet[0] & 0x0F) as usize) * 4;
        if packet.len() >= ihl + 8 && packet[ihl] == 0 {
            let rseq = u16::from_be_bytes([packet[ihl + 6], packet[ihl + 7]]);
            let mut g = state.lock().unwrap();
            if let Some((exp, at)) = g.ping_sent_at {
                if exp == rseq {
                    let ms = at.elapsed().as_secs_f64() * 1000.0;
                    g.events.insert(0, format!("✅ Pong<-{sender_vip} #{rseq}: {ms:.1} ms [{via}]"));
                    g.ping_sent_at = None;
                    return;
                }
            }
        }
    }

    if let Some(reply) = try_build_icmp_echo_reply(packet, local_vip) {
        let _ = node.send_packet(&reply);
    }
}

fn write_http(stream: &mut TcpStream, status: &str, ctype: &str, body: &[u8]) {
    let hdr = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(hdr.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

fn escape_json(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', " ").replace('\r', "")
}

fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn url_decode(s: &str) -> String {
    let mut out = Vec::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(b);
                i += 3;
                continue;
            }
        } else if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

const HTML_UI: &str = r#"<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>NexoMesh Desktop</title>
<style>
  body{margin:0;background:#0b1120;color:#f8fafc;font-family:system-ui,-apple-system,sans-serif;padding:20px}
  .wrap{max-width:680px;margin:0 auto;display:grid;gap:14px}
  .card{background:#111827;border:1px solid #1e293b;border-radius:16px;padding:16px}
  h1{margin:0 0 8px;font-size:18px;display:flex;align-items:center;gap:8px}
  .sub{color:#94a3b8;font-size:12px;margin-bottom:10px}
  .row{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:8px}
  input[type=text]{flex:1;min-width:160px;background:#0f172a;border:1px solid #334155;color:#f8fafc;padding:9px 11px;border-radius:10px;font-size:13px}
  button{border:0;border-radius:10px;padding:9px 13px;font-weight:600;cursor:pointer;font-size:12px}
  .primary{background:#059669;color:#fff}
  .info{background:#0284c7;color:#fff}
  .ghost{background:#1e293b;color:#cbd5e1}
  .log{background:#0f172a;border-radius:10px;padding:10px;font-size:12px;max-height:180px;overflow:auto;display:grid;gap:5px}
  .badge{display:inline-block;background:#064e3b;color:#34d399;padding:3px 9px;border-radius:999px;font-size:11px}
  .warn{background:#1e293b;color:#fbbf24}
  code{background:#0f172a;padding:3px 6px;border-radius:6px;font-size:11px;word-break:break-all;display:block;margin-top:6px;color:#7dd3fc}
</style>
</head>
<body>
<div class="wrap">
  <div class="card">
    <h1>🛡️ NexoMesh PC</h1>
    <div class="sub" id="ipInfo">🌐 Cargando...</div>
    <div class="row">
      <button class="primary" id="rxBtn" onclick="startRx()">📥 Receptor (:51821)</button>
      <button class="info" onclick="openFolder()">📂 Descargas</button>
      <button class="ghost" onclick="testStun()">🌐 STUN</button>
      <button class="ghost" onclick="genInvite()">🔗 Invitación</button>
    </div>
    <code id="inviteOut" style="display:none"></code>
  </div>

  <div class="card">
    <h1>🌍 Conexión Remota (Fuera de LAN)</h1>
    <div class="row">
      <input type="text" id="joinUri" placeholder="Pegar enlace nexomesh://join?... del celular"/>
      <button class="ghost" onclick="applyJoin()">📲 Cargar</button>
    </div>
    <div class="row">
      <input type="text" id="relayUrl" placeholder="Relay DERP (ej. ws://tu-servidor:8080/ws)"/>
      <input type="text" id="peerVip" placeholder="IP Par (10.0.0.1)" style="max-width:120px"/>
    </div>
    <div class="row">
      <button class="primary" id="tunBtn" onclick="startTunnel()">🔌 Conectar Túnel + Relay</button>
      <button class="info" onclick="sendPing()">📡 Ping P2P</button>
    </div>
  </div>

  <div class="card">
    <h1>📤 Enviar Archivo (LAN o Remoto)</h1>
    <div class="row">
      <input type="text" id="targetIp" placeholder="IP destino (ej. 10.0.0.1 o 192.168.1.45)"/>
      <input type="file" id="filePick" style="color:#cbd5e1;font-size:12px"/>
    </div>
    <button class="primary" style="width:100%" onclick="sendFile()">🚀 Enviar Archivo</button>
  </div>

  <div class="card">
    <h1>📋 Actividad</h1>
    <div class="log" id="logs"></div>
  </div>
</div>
<script>
let initDone = false;
async function refresh(){
  const r = await fetch('/api/status'); const d = await r.json();
  const rel = d.relayConnected ? '<span class="badge">Relay OK</span>' : '<span class="badge warn">Sin Relay</span>';
  const udp = d.directUdp ? '<span class="badge">UDP Directo</span>' : '';
  document.getElementById('ipInfo').innerHTML = `🌐 LAN: <span class="badge">${d.lanIp}:51821</span> · VPN: <span class="badge">${d.localVip}</span> ${rel} ${udp}`;
  document.getElementById('rxBtn').textContent = d.receiverActive ? '✅ Receptor Activo' : '📥 Receptor (:51821)';
  document.getElementById('tunBtn').textContent = d.tunnelActive ? '✅ Túnel Activo' : '🔌 Conectar Túnel + Relay';
  if(!initDone){
    if(d.relayUrl) document.getElementById('relayUrl').value = d.relayUrl;
    if(d.peerVip) document.getElementById('peerVip').value = d.peerVip;
    initDone = true;
  }
  document.getElementById('logs').innerHTML = d.events.map(e=>`<div>${e}</div>`).join('') || '<div>📭 Sin eventos</div>';
}
async function startRx(){ await fetch('/api/receiver/start',{method:'POST'}); refresh(); }
async function openFolder(){ await fetch('/api/open-folder',{method:'POST'}); }
async function testStun(){ await fetch('/api/stun'); refresh(); }
async function applyJoin(){
  const u = document.getElementById('joinUri').value.trim();
  if(!u) return;
  await fetch('/api/join',{method:'POST',body:u});
  initDone = false; refresh();
}
async function startTunnel(){
  const relayUrl = document.getElementById('relayUrl').value.trim();
  const peerVip = document.getElementById('peerVip').value.trim();
  await fetch('/api/tunnel/start',{method:'POST',body:JSON.stringify({relayUrl,peerVip})});
  refresh();
}
async function sendPing(){ await fetch('/api/ping',{method:'POST'}); refresh(); }
async function genInvite(){
  const r = await fetch('/api/invite'); const d = await r.json();
  const el = document.getElementById('inviteOut');
  el.style.display = 'block'; el.textContent = d.uri;
}
async function sendFile(){
  const to = document.getElementById('targetIp').value.trim();
  const f = document.getElementById('filePick').files[0];
  if(!f){ alert('Selecciona un archivo'); return; }
  const r = await fetch(`/api/send?to=${encodeURIComponent(to)}&name=${encodeURIComponent(f.name)}`,{method:'POST',body:f});
  const d = await r.json();
  if(!d.ok) alert('Error: ' + d.error);
  refresh();
}
refresh(); setInterval(refresh, 1500);
</script>
</body>
</html>
"#;
