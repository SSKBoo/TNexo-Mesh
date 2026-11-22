use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use wintun::{Adapter, Session};

pub struct WinTunHandle {
    pub session: Arc<Session>,
    _adapter: Arc<Adapter>,
}

fn find_wintun_dll() -> Option<PathBuf> {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let p = dir.join("wintun.dll");
            if p.exists() {
                return Some(p);
            }
        }
    }
    let cwd = PathBuf::from("wintun.dll");
    if cwd.exists() {
        return Some(cwd);
    }
    None
}

pub fn try_start_wintun(local_vip: &str) -> Result<WinTunHandle, String> {
    let dll_path = find_wintun_dll()
        .ok_or_else(|| "wintun.dll no encontrada junto al ejecutable (usando modo Userspace)".to_string())?;

    let wintun = unsafe { wintun::load_from_path(&dll_path) }
        .map_err(|e| format!("No se pudo cargar wintun.dll: {e}"))?;

    let adapter = Adapter::open(&wintun, "NexoMesh")
        .or_else(|_| Adapter::create(&wintun, "NexoMesh", "NexoMesh", None))
        .map_err(|e| format!("No se pudo abrir/crear adaptador NexoMesh (¿ejecutar como Administrador?): {e}"))?;

    // Asignar IP virtual en la subred 10.0.0.0/24
    let status = Command::new("netsh")
        .args([
            "interface",
            "ip",
            "set",
            "address",
            "name=NexoMesh",
            "static",
            local_vip,
            "255.255.255.0",
        ])
        .status()
        .map_err(|e| format!("Error ejecutando netsh: {e}"))?;

    if !status.success() {
        return Err("netsh falló al asignar IP (ejecuta como Administrador)".to_string());
    }

    let _ = Command::new("netsh")
        .args(["interface", "ipv4", "set", "subinterface", "NexoMesh", "mtu=1380", "store=active"])
        .status();

    let session = Arc::new(
        adapter
            .start_session(wintun::MAX_RING_CAPACITY)
            .map_err(|e| format!("Error iniciando sesión Wintun: {e}"))?,
    );

    Ok(WinTunHandle {
        session,
        _adapter: adapter,
    })
}

pub fn write_ip_packet(session: &Arc<Session>, ip_packet: &[u8]) {
    if ip_packet.len() > u16::MAX as usize {
        return;
    }
    if let Ok(mut pkt) = session.allocate_send_packet(ip_packet.len() as u16) {
        pkt.bytes_mut().copy_from_slice(ip_packet);
        session.send_packet(pkt);
    }
}
