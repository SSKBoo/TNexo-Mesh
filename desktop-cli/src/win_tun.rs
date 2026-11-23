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

    // Asignar IP virtual (soporta CGNAT 100.64.0.0/10 y subred legacy 10.0.0.0/24)
    let mask = if local_vip.starts_with("100.") { "255.192.0.0" } else { "255.255.255.0" };
    let status = Command::new("netsh")
        .args([
            "interface",
            "ip",
            "set",
            "address",
            "name=NexoMesh",
            "static",
            local_vip,
            mask,
        ])
        .status()
        .map_err(|e| format!("Error ejecutando netsh: {e}"))?;

    if !status.success() {
        return Err("netsh falló al asignar IP (ejecuta como Administrador)".to_string());
    }

    let _ = Command::new("netsh")
        .args(["interface", "ipv4", "add", "route", "100.64.0.0/10", "NexoMesh"])
        .status();
    let _ = Command::new("netsh")
        .args(["interface", "ipv4", "add", "route", "10.0.0.0/24", "NexoMesh"])
        .status();

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

/// Registra Split DNS en Windows vía NRPT para `.nexomesh` y `.mesh` apuntando al resolver local.
pub fn configure_windows_split_dns(dns_server: &str) {
    let ps = format!(
        "Get-DnsClientNrptRule | Where-Object {{ $_.Comment -eq 'NexoMesh' }} | Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue; \
         Add-DnsClientNrptRule -Namespace '.nexomesh' -NameServers '{dns_server}' -Comment 'NexoMesh' -ErrorAction SilentlyContinue; \
         Add-DnsClientNrptRule -Namespace '.mesh' -NameServers '{dns_server}' -Comment 'NexoMesh' -ErrorAction SilentlyContinue"
    );
    let _ = Command::new("powershell")
        .args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", &ps])
        .status();
}

/// Elimina las reglas NRPT de NexoMesh al detener el túnel VPN en Windows.
pub fn restore_windows_split_dns() {
    let ps = "Get-DnsClientNrptRule | Where-Object { $_.Comment -eq 'NexoMesh' } | Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue";
    let _ = Command::new("powershell")
        .args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", ps])
        .status();
}
