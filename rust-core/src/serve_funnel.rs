//! Servicios Capa 7 estilo Tailscale (`Serve` y `Funnel`):
//! - `Serve`: proxy HTTP/TLS interno que expone servicios locales exclusivamente a pares dentro de la malla (`100.64.0.0/10` / `10.0.0.0/24`) bajo `.mesh` / `.nexomesh`.
//! - `Funnel`: proxy de ingreso público con cabeceras de origen (`X-NexoMesh-Funnel: 1`) hacia el servicio local sin abrir puertos directos en el firewall anfitrión.

use crate::routing::is_mesh_ipv4;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExposureMode {
    ServeMeshOnly,
    FunnelPublic,
}

#[derive(Clone, Debug)]
pub struct ServiceBinding {
    pub domain: String,
    pub target_addr: String,
    pub mode: ExposureMode,
}

#[derive(Default)]
pub struct ServeRegistry {
    bindings: HashMap<String, ServiceBinding>,
}

impl ServeRegistry {
    pub fn new() -> Self {
        Self {
            bindings: HashMap::new(),
        }
    }

    pub fn register(&mut self, domain: &str, target_addr: &str, mode: ExposureMode) {
        let norm = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        self.bindings.insert(
            norm.clone(),
            ServiceBinding {
                domain: norm,
                target_addr: target_addr.to_string(),
                mode,
            },
        );
    }

    pub fn get(&self, domain: &str) -> Option<&ServiceBinding> {
        let norm = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        self.bindings.get(&norm)
    }

    pub fn list(&self) -> Vec<ServiceBinding> {
        self.bindings.values().cloned().collect()
    }
}

fn extract_forwarded_for(req_text: &str) -> Option<String> {
    for line in req_text.lines() {
        if line.to_ascii_lowercase().starts_with("x-forwarded-for:") {
            let val = line.split_once(':')?.1.split(',').next()?.trim();
            if !val.is_empty() {
                return Some(val.to_string());
            }
        }
    }
    None
}

fn handle_proxy_conn(mut client: TcpStream, peer: SocketAddr, target_addr: &str, mesh_only: bool) {
    let _ = client.set_read_timeout(Some(Duration::from_secs(2)));
    let mut buf = [0u8; 8192];
    let Ok(n) = client.read(&mut buf) else {
        return;
    };
    if n == 0 {
        return;
    }

    let req_text = String::from_utf8_lossy(&buf[..n]);
    let effective_ip = extract_forwarded_for(&req_text).unwrap_or_else(|| peer.ip().to_string());

    if mesh_only && !is_mesh_ipv4(&effective_ip) {
        let _ = client.write_all(
            b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: 27\r\nConnection: close\r\n\r\nServe: mesh peers only\r\n\r\n",
        );
        return;
    }

    let Ok(mut upstream) = TcpStream::connect(target_addr) else {
        let _ = client.write_all(
            b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 11\r\nConnection: close\r\n\r\nBad Gateway",
        );
        return;
    };
    let _ = upstream.set_read_timeout(Some(Duration::from_secs(3)));

    // Inyectar cabecera de trazabilidad Serve/Funnel antes del fin de headers HTTP
    let outbound: Vec<u8> = if let Some(hdr_end) = req_text.find("\r\n\r\n") {
        let mode_hdr = if mesh_only {
            "X-NexoMesh-Serve: 1\r\n"
        } else {
            "X-NexoMesh-Funnel: 1\r\n"
        };
        let mut v = Vec::with_capacity(n + mode_hdr.len());
        v.extend_from_slice(&buf[..hdr_end + 2]);
        v.extend_from_slice(mode_hdr.as_bytes());
        v.extend_from_slice(&buf[hdr_end + 2..n]);
        v
    } else {
        buf[..n].to_vec()
    };

    if upstream.write_all(&outbound).is_err() {
        return;
    }
    let _ = upstream.shutdown(std::net::Shutdown::Write);

    let mut resp_buf = [0u8; 8192];
    while let Ok(rn) = upstream.read(&mut resp_buf) {
        if rn == 0 {
            break;
        }
        if client.write_all(&resp_buf[..rn]).is_err() {
            break;
        }
    }
}

/// Inicia un proxy reverso L7 para `Serve` (`mesh_only=true`) o `Funnel` (`mesh_only=false`).
pub fn start_serve_funnel_proxy(
    listen_addr: &str,
    target_addr: &str,
    mesh_only: bool,
) -> std::io::Result<(SocketAddr, Arc<AtomicBool>)> {
    let listener = TcpListener::bind(listen_addr)?;
    listener.set_nonblocking(true)?;
    let bound = listener.local_addr()?;
    let running = Arc::new(AtomicBool::new(true));
    let running_bg = Arc::clone(&running);
    let target = target_addr.to_string();

    std::thread::spawn(move || {
        while running_bg.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, peer)) => {
                    let _ = stream.set_nonblocking(false);
                    let tgt = target.clone();
                    std::thread::spawn(move || handle_proxy_conn(stream, peer, &tgt, mesh_only));
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(15));
                }
                Err(_) => break,
            }
        }
    });

    Ok((bound, running))
}
