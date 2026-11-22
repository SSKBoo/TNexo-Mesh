use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;

use crate::{handle_incoming_file_conn, probe_stun, send_bytes_p2p};

struct GuiState {
    receiver_active: bool,
    events: Vec<String>,
    save_dir: PathBuf,
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
    let save_dir = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("NexoMesh_Recibidos");
    let _ = fs::create_dir_all(&save_dir);

    let state = Arc::new(Mutex::new(GuiState {
        receiver_active: false,
        events: vec![format!("📂 Carpeta: {}", save_dir.display())],
        save_dir,
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
            let guard = state.lock().unwrap();
            let events_json = guard
                .events
                .iter()
                .map(|e| format!("\"{}\"", escape_json(e)))
                .collect::<Vec<_>>()
                .join(",");
            let json = format!(
                "{{\"lanIp\":\"{}\",\"receiverActive\":{},\"saveDir\":\"{}\",\"events\":[{}]}}",
                escape_json(&lan),
                guard.receiver_active,
                escape_json(&guard.save_dir.display().to_string()),
                events_json
            );
            write_http(&mut stream, "200 OK", "application/json", json.as_bytes());
        }
        ("POST", "/api/receiver/start") => {
            let mut guard = state.lock().unwrap();
            if !guard.receiver_active {
                guard.receiver_active = true;
                let dir = guard.save_dir.clone();
                let st_bg = Arc::clone(&state);
                guard.events.insert(0, "📥 Receptor TCP :51821 activado".to_string());
                drop(guard);
                thread::spawn(move || {
                    if let Ok(rx_listener) = TcpListener::bind("0.0.0.0:51821") {
                        for conn in rx_listener.incoming().flatten() {
                            if let Some((fname, size)) = handle_incoming_file_conn(conn, &dir) {
                                let mut g = st_bg.lock().unwrap();
                                g.events.insert(0, format!("📥 Recibido '{fname}' ({size} B)"));
                            }
                        }
                    } else {
                        let mut g = st_bg.lock().unwrap();
                        g.receiver_active = false;
                        g.events.insert(0, "❌ Puerto :51821 ocupado".to_string());
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
            let json = format!("{{\"result\":\"{}\"}}", escape_json(&res));
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
            let max_upload = 64 * 1024 * 1024;
            if content_len == 0 || content_len > max_upload {
                write_http(&mut stream, "400 Bad Request", "application/json", b"{\"ok\":false,\"error\":\"tamano invalido\"}");
                return;
            }
            let mut body = vec![0u8; content_len];
            if reader.read_exact(&mut body).is_err() {
                write_http(&mut stream, "400 Bad Request", "application/json", b"{\"ok\":false,\"error\":\"lectura incompleta\"}");
                return;
            }
            match send_bytes_p2p(&name, &body, &to) {
                Ok(msg) => {
                    state.lock().unwrap().events.insert(0, format!("📤 {msg}"));
                    let json = format!("{{\"ok\":true,\"message\":\"{}\"}}", escape_json(&msg));
                    write_http(&mut stream, "200 OK", "application/json", json.as_bytes());
                }
                Err(e) => {
                    state.lock().unwrap().events.insert(0, format!("💔 Error envío: {e}"));
                    let json = format!("{{\"ok\":false,\"error\":\"{}\"}}", escape_json(&e));
                    write_http(&mut stream, "500 Internal Server Error", "application/json", json.as_bytes());
                }
            }
        }
        _ => write_http(&mut stream, "404 Not Found", "text/plain", b"not found"),
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
  body{margin:0;background:#0b1120;color:#f8fafc;font-family:system-ui,-apple-system,sans-serif;padding:24px}
  .wrap{max-width:640px;margin:0 auto;display:grid;gap:16px}
  .card{background:#111827;border:1px solid #1e293b;border-radius:16px;padding:18px}
  h1{margin:0 0 6px;font-size:20px;display:flex;align-items:center;gap:8px}
  .sub{color:#94a3b8;font-size:13px;margin-bottom:12px}
  .row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
  input[type=text]{flex:1;min-width:180px;background:#0f172a;border:1px solid #334155;color:#f8fafc;padding:10px 12px;border-radius:10px;font-size:14px}
  button{border:0;border-radius:10px;padding:10px 14px;font-weight:600;cursor:pointer;font-size:13px}
  .primary{background:#059669;color:#fff}
  .info{background:#0284c7;color:#fff}
  .ghost{background:#1e293b;color:#cbd5e1}
  .log{background:#0f172a;border-radius:10px;padding:10px 12px;font-size:12px;max-height:220px;overflow:auto;display:grid;gap:6px}
  .badge{display:inline-block;background:#064e3b;color:#34d399;padding:4px 10px;border-radius:999px;font-size:12px}
</style>
</head>
<body>
<div class="wrap">
  <div class="card">
    <h1>🛡️ NexoMesh PC</h1>
    <div class="sub" id="ipInfo">🌐 Detectando IP LAN...</div>
    <div class="row">
      <button class="primary" id="rxBtn" onclick="startRx()">📥 Activar Receptor (:51821)</button>
      <button class="info" onclick="openFolder()">📂 Abrir carpeta</button>
      <button class="ghost" onclick="testStun()">🌐 STUN</button>
    </div>
  </div>
  <div class="card">
    <h1>📤 Enviar a Celular</h1>
    <div class="row" style="margin-bottom:10px">
      <input type="text" id="targetIp" placeholder="IP del celular (ej. 192.168.1.45 o 10.0.0.1)"/>
      <input type="file" id="filePick" style="color:#cbd5e1;font-size:12px"/>
    </div>
    <button class="primary" style="width:100%" onclick="sendFile()">🚀 Enviar por TCP :51821</button>
  </div>
  <div class="card">
    <h1>📋 Actividad</h1>
    <div class="log" id="logs"></div>
  </div>
</div>
<script>
async function refresh(){
  const r = await fetch('/api/status'); const d = await r.json();
  document.getElementById('ipInfo').innerHTML = `🌐 IP LAN PC: <span class="badge">${d.lanIp}:51821</span>`;
  document.getElementById('rxBtn').textContent = d.receiverActive ? '✅ Receptor Activo (:51821)' : '📥 Activar Receptor (:51821)';
  document.getElementById('logs').innerHTML = d.events.map(e=>`<div>${e}</div>`).join('') || '<div>📭 Sin eventos</div>';
}
async function startRx(){ await fetch('/api/receiver/start',{method:'POST'}); refresh(); }
async function openFolder(){ await fetch('/api/open-folder',{method:'POST'}); }
async function testStun(){
  const r = await fetch('/api/stun'); const d = await r.json();
  alert(d.result);
}
async function sendFile(){
  const to = document.getElementById('targetIp').value.trim();
  const f = document.getElementById('filePick').files[0];
  if(!to || !f){ alert('Ingresa IP y selecciona un archivo'); return; }
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
