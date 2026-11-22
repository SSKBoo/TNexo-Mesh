//! Cliente WebSocket RFC 6455 mínimo (ws:// y wss:// vía rustls en escritorio)
//! para conectar el nodo userspace Rust al relay DERP del backend.

use anyhow::{anyhow, Result};
use rand_core::{OsRng, RngCore};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

#[derive(Debug, PartialEq, Eq)]
pub enum WsFrame {
    Text(String),
    Binary(Vec<u8>),
    Closed,
}

enum WsStream {
    Plain(TcpStream),
    #[cfg(not(target_os = "android"))]
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
}

impl Read for WsStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            WsStream::Plain(s) => s.read(buf),
            #[cfg(not(target_os = "android"))]
            WsStream::Tls(s) => s.read(buf),
        }
    }
}

impl Write for WsStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            WsStream::Plain(s) => s.write(buf),
            #[cfg(not(target_os = "android"))]
            WsStream::Tls(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            WsStream::Plain(s) => s.flush(),
            #[cfg(not(target_os = "android"))]
            WsStream::Tls(s) => s.flush(),
        }
    }
}

pub struct WsClient {
    stream: WsStream,
    buffered: Vec<u8>,
}

impl WsClient {
    /// Conecta a un endpoint `ws://host:port/path` o `wss://host[:port]/path`.
    pub fn connect(url: &str) -> Result<Self> {
        let (is_tls, rest) = if let Some(r) = url.strip_prefix("wss://") {
            (true, r)
        } else if let Some(r) = url.strip_prefix("ws://") {
            (false, r)
        } else {
            return Err(anyhow!("esquema WebSocket no soportado (usa ws:// o wss://): {url}"));
        };

        let (host_port, path) = match rest.find('/') {
            Some(idx) => (&rest[..idx], &rest[idx..]),
            None => (rest, "/"),
        };
        let default_port = if is_tls { 443 } else { 80 };
        let (host, addr) = if let Some((h, _p)) = host_port.rsplit_once(':') {
            (h.to_string(), host_port.to_string())
        } else {
            (host_port.to_string(), format!("{host_port}:{default_port}"))
        };

        let tcp = TcpStream::connect(&addr)?;
        tcp.set_read_timeout(Some(Duration::from_millis(50)))?;
        tcp.set_nodelay(true)?;

        let mut stream = if is_tls {
            connect_tls(tcp, &host)?
        } else {
            WsStream::Plain(tcp)
        };

        let mut key_bytes = [0u8; 16];
        OsRng.fill_bytes(&mut key_bytes);
        let ws_key = base64_encode(&key_bytes);

        let req = format!(
            "GET {path} HTTP/1.1\r\n\
             Host: {host_port}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {ws_key}\r\n\
             Sec-WebSocket-Version: 13\r\n\r\n"
        );
        stream.write_all(req.as_bytes())?;
        stream.flush()?;

        // Leer cabecera HTTP hasta \r\n\r\n preservando bytes sobrantes en `buffered`.
        let mut hdr_buf = Vec::with_capacity(512);
        let mut byte = [0u8; 1];
        let mut header_end = None;
        for _ in 0..8192 {
            match stream.read(&mut byte) {
                Ok(0) => break,
                Ok(_) => {
                    hdr_buf.push(byte[0]);
                    if hdr_buf.ends_with(b"\r\n\r\n") {
                        header_end = Some(hdr_buf.len());
                        break;
                    }
                }
                Err(e) if is_timeout(&e) => continue,
                Err(e) => return Err(e.into()),
            }
        }
        let end = header_end.ok_or_else(|| anyhow!("respuesta HTTP incompleta en handshake WS"))?;
        let status_line = String::from_utf8_lossy(&hdr_buf[..end]);
        let first_line = status_line.lines().next().unwrap_or("");
        if !first_line.contains("101") {
            return Err(anyhow!("handshake WebSocket rechazado: {}", first_line.trim()));
        }
        Ok(Self {
            stream,
            buffered: Vec::new(),
        })
    }

    pub fn send_text(&mut self, text: &str) -> Result<()> {
        self.send_raw(0x1, text.as_bytes())
    }

    pub fn send_binary(&mut self, data: &[u8]) -> Result<()> {
        self.send_raw(0x2, data)
    }

    fn send_raw(&mut self, opcode: u8, payload: &[u8]) -> Result<()> {
        let mut header = Vec::with_capacity(14);
        header.push(0x80 | (opcode & 0x0F));
        let len = payload.len();
        if len < 126 {
            header.push(0x80 | (len as u8));
        } else if len <= 65535 {
            header.push(0x80 | 126);
            header.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            header.push(0x80 | 127);
            header.extend_from_slice(&(len as u64).to_be_bytes());
        }
        let mut mask = [0u8; 4];
        OsRng.fill_bytes(&mut mask);
        header.extend_from_slice(&mask);

        let mut masked = Vec::with_capacity(len);
        for (i, b) in payload.iter().enumerate() {
            masked.push(b ^ mask[i % 4]);
        }

        self.stream.write_all(&header)?;
        self.stream.write_all(&masked)?;
        self.stream.flush()?;
        Ok(())
    }

    /// Intenta leer un frame sin bloquear indefinidamente (usa timeout de 50ms).
    pub fn recv_frame(&mut self) -> Result<Option<WsFrame>> {
        let mut hdr = [0u8; 2];
        if !self.read_exact_nonblocking(&mut hdr)? {
            return Ok(None);
        }
        let opcode = hdr[0] & 0x0F;
        let masked = (hdr[1] & 0x80) != 0;
        let mut len = (hdr[1] & 0x7F) as usize;
        if len == 126 {
            let mut ext = [0u8; 2];
            self.read_exact_blocking(&mut ext)?;
            len = u16::from_be_bytes(ext) as usize;
        } else if len == 127 {
            let mut ext = [0u8; 8];
            self.read_exact_blocking(&mut ext)?;
            len = u64::from_be_bytes(ext) as usize;
        }
        let mut mask = [0u8; 4];
        if masked {
            self.read_exact_blocking(&mut mask)?;
        }
        let mut payload = vec![0u8; len];
        if len > 0 {
            self.read_exact_blocking(&mut payload)?;
        }
        if masked {
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= mask[i % 4];
            }
        }
        match opcode {
            0x8 => Ok(Some(WsFrame::Closed)),
            0x9 => {
                let _ = self.send_raw(0xA, &payload);
                Ok(None)
            }
            0xA => Ok(None),
            0x1 => Ok(Some(WsFrame::Text(String::from_utf8_lossy(&payload).into_owned()))),
            0x2 => Ok(Some(WsFrame::Binary(payload))),
            _ => Ok(None),
        }
    }

    fn read_exact_nonblocking(&mut self, buf: &mut [u8]) -> Result<bool> {
        if self.buffered.len() >= buf.len() {
            buf.copy_from_slice(&self.buffered[..buf.len()]);
            self.buffered.drain(..buf.len());
            return Ok(true);
        }
        let mut pos = 0;
        if !self.buffered.is_empty() {
            pos = self.buffered.len();
            buf[..pos].copy_from_slice(&self.buffered);
            self.buffered.clear();
        }
        while pos < buf.len() {
            match self.stream.read(&mut buf[pos..]) {
                Ok(0) => return Err(anyhow!("conexión WebSocket cerrada")),
                Ok(n) => pos += n,
                Err(e) if pos == 0 && is_timeout(&e) => return Ok(false),
                Err(e) if is_timeout(&e) => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(true)
    }

    fn read_exact_blocking(&mut self, buf: &mut [u8]) -> Result<()> {
        let mut pos = 0;
        if !self.buffered.is_empty() {
            let take = self.buffered.len().min(buf.len());
            buf[..take].copy_from_slice(&self.buffered[..take]);
            self.buffered.drain(..take);
            pos = take;
        }
        while pos < buf.len() {
            match self.stream.read(&mut buf[pos..]) {
                Ok(0) => return Err(anyhow!("conexión WebSocket cerrada")),
                Ok(n) => pos += n,
                Err(e) if is_timeout(&e) => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }
}

#[cfg(not(target_os = "android"))]
fn connect_tls(tcp: TcpStream, host: &str) -> Result<WsStream> {
    use rustls::pki_types::ServerName;
    use std::sync::Arc;

    let root_store = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|_| anyhow!("nombre TLS inválido: {host}"))?;
    let conn = rustls::ClientConnection::new(Arc::new(config), server_name)
        .map_err(|e| anyhow!("error iniciando TLS: {e}"))?;
    Ok(WsStream::Tls(Box::new(rustls::StreamOwned::new(conn, tcp))))
}

#[cfg(target_os = "android")]
fn connect_tls(_tcp: TcpStream, _host: &str) -> Result<WsStream> {
    Err(anyhow!("wss:// en Android se gestiona vía RelayClient (OkHttp)"))
}

fn is_timeout(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

pub fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(((input.len() + 2) / 3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 { TABLE[((n >> 6) & 63) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { TABLE[(n & 63) as usize] as char } else { '=' });
    }
    out
}

pub fn base64_decode(input: &str) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity((input.len() * 3) / 4);
    let mut buf: u32 = 0;
    let mut bits: u8 = 0;
    for b in input.bytes() {
        if b == b'=' || b.is_ascii_whitespace() {
            continue;
        }
        let val = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return Err(anyhow!("carácter base64 inválido")),
        };
        buf = (buf << 6) | (val as u32);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xFF) as u8);
        }
    }
    Ok(out)
}

/// Extrae un campo string plano `"key":"value"` de un JSON sin dependencias externas.
pub fn extract_json_str(json: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let start = json.find(&needle)? + needle.len();
    let rest = json[start..].trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    let mut out = String::new();
    let mut escaped = false;
    for ch in rest.chars() {
        if escaped {
            out.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == '"' {
            return Some(out);
        } else {
            out.push(ch);
        }
    }
    None
}
