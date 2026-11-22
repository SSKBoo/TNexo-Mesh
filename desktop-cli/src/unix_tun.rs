//! Soporte de interfaz TUN nativa para Linux (`/dev/net/tun`) y macOS (`utun`).
//! Permite crear el adaptador `10.0.0.x/24` sin depender de drivers externos.

#[cfg(target_os = "linux")]
pub fn open_linux_tun_info() -> &'static str {
    "/dev/net/tun (IFF_TUN | IFF_NO_PI) disponible con CAP_NET_ADMIN"
}

#[cfg(target_os = "macos")]
pub fn open_macos_utun_info() -> &'static str {
    "utun (PF_SYSTEM / UTUN_CONTROL_NAME) disponible con root"
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn configure_unix_tun_routes(iface: &str, local_vip: &str) -> Result<(), String> {
    use std::process::Command;
    #[cfg(target_os = "linux")]
    {
        let st = Command::new("ip")
            .args(["addr", "add", &format!("{local_vip}/24"), "dev", iface])
            .status()
            .map_err(|e| format!("ip addr error: {e}"))?;
        if !st.success() {
            return Err("ip addr add falló (requiere sudo/CAP_NET_ADMIN)".to_string());
        }
        let _ = Command::new("ip").args(["link", "set", "dev", iface, "mtu", "1380", "up"]).status();
    }
    #[cfg(target_os = "macos")]
    {
        let st = Command::new("ifconfig")
            .args([iface, "inet", local_vip, local_vip, "netmask", "255.255.255.0", "mtu", "1380", "up"])
            .status()
            .map_err(|e| format!("ifconfig error: {e}"))?;
        if !st.success() {
            return Err("ifconfig falló (requiere sudo)".to_string());
        }
    }
    Ok(())
}
