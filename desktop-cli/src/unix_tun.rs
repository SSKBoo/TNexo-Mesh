//! Soporte de interfaz TUN nativa para Linux (`/dev/net/tun`) y macOS (`utun`),
//! además de rutas de Subnet Router y NAT masquerading para Exit Node.

#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::fd::RawFd;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::process::Command;

#[cfg(target_os = "linux")]
pub fn open_linux_tun_info() -> &'static str {
    "/dev/net/tun (IFF_TUN | IFF_NO_PI) disponible con CAP_NET_ADMIN"
}

#[cfg(target_os = "macos")]
pub fn open_macos_utun_info() -> &'static str {
    "utun (PF_SYSTEM / UTUN_CONTROL_NAME) disponible con root"
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub struct UnixTun {
    pub name: String,
    fd: RawFd,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl UnixTun {
    /// Abre una interfaz TUN nativa (`nm0` en Linux, `utunN` en macOS) y configura la IP virtual.
    pub fn open(local_vip: &str) -> Result<Self, String> {
        let tun = Self::open_raw()?;
        configure_unix_tun_routes(&tun.name, local_vip)?;
        Ok(tun)
    }

    #[cfg(target_os = "linux")]
    fn open_raw() -> Result<Self, String> {
        #[repr(C)]
        struct IfReq {
            ifr_name: [u8; 16],
            ifr_flags: libc::c_short,
            _pad: [u8; 22],
        }

        const IFF_TUN: libc::c_short = 0x0001;
        const IFF_NO_PI: libc::c_short = 0x1000;
        const TUNSETIFF: libc::c_ulong = 0x4004_54ca;

        let path = b"/dev/net/tun\0";
        let fd = unsafe { libc::open(path.as_ptr() as *const libc::c_char, libc::O_RDWR) };
        if fd < 0 {
            return Err("No se pudo abrir /dev/net/tun (requiere root/CAP_NET_ADMIN)".to_string());
        }

        let mut ifr = IfReq {
            ifr_name: [0; 16],
            ifr_flags: IFF_TUN | IFF_NO_PI,
            _pad: [0; 22],
        };
        let dev = b"nm0";
        ifr.ifr_name[..dev.len()].copy_from_slice(dev);

        let rc = unsafe { libc::ioctl(fd, TUNSETIFF as _, &mut ifr) };
        if rc < 0 {
            unsafe { libc::close(fd) };
            return Err("ioctl TUNSETIFF falló (requiere CAP_NET_ADMIN)".to_string());
        }

        let end = ifr.ifr_name.iter().position(|&b| b == 0).unwrap_or(16);
        let name = String::from_utf8_lossy(&ifr.ifr_name[..end]).to_string();
        Ok(Self { name, fd })
    }

    #[cfg(target_os = "macos")]
    fn open_raw() -> Result<Self, String> {
        const PF_SYSTEM: libc::c_int = 32;
        const SYSPROTO_CONTROL: libc::c_int = 2;
        const AF_SYS_CONTROL: u16 = 2;
        const CTLIOCGINFO: libc::c_ulong = 0xc064_4e03;
        const UTUN_OPT_IFNAME: libc::c_int = 2;

        #[repr(C)]
        struct CtlInfo {
            ctl_id: u32,
            ctl_name: [u8; 96],
        }
        #[repr(C)]
        struct SockAddrCtl {
            sc_len: u8,
            sc_family: u8,
            ss_sysaddr: u16,
            sc_id: u32,
            sc_unit: u32,
            sc_reserved: [u32; 5],
        }

        let fd = unsafe { libc::socket(PF_SYSTEM, libc::SOCK_DGRAM, SYSPROTO_CONTROL) };
        if fd < 0 {
            return Err("socket PF_SYSTEM falló en macOS".to_string());
        }

        let mut info = CtlInfo {
            ctl_id: 0,
            ctl_name: [0; 96],
        };
        let ctrl_name = b"com.apple.net.utun_control";
        info.ctl_name[..ctrl_name.len()].copy_from_slice(ctrl_name);

        if unsafe { libc::ioctl(fd, CTLIOCGINFO as _, &mut info) } < 0 {
            unsafe { libc::close(fd) };
            return Err("CTLIOCGINFO utun falló".to_string());
        }

        let addr = SockAddrCtl {
            sc_len: std::mem::size_of::<SockAddrCtl>() as u8,
            sc_family: PF_SYSTEM as u8,
            ss_sysaddr: AF_SYS_CONTROL,
            sc_id: info.ctl_id,
            sc_unit: 0, // Asigna el siguiente utunN libre automáticamente
            sc_reserved: [0; 5],
        };

        if unsafe {
            libc::connect(
                fd,
                (&addr as *const SockAddrCtl) as *const libc::sockaddr,
                std::mem::size_of::<SockAddrCtl>() as libc::socklen_t,
            )
        } < 0
        {
            unsafe { libc::close(fd) };
            return Err("connect utun falló (requiere sudo)".to_string());
        }

        let mut ifname = [0u8; 32];
        let mut ifname_len = ifname.len() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                fd,
                SYSPROTO_CONTROL,
                UTUN_OPT_IFNAME,
                ifname.as_mut_ptr() as *mut libc::c_void,
                &mut ifname_len,
            )
        } < 0
        {
            unsafe { libc::close(fd) };
            return Err("getsockopt UTUN_OPT_IFNAME falló".to_string());
        }
        let end = ifname.iter().position(|&b| b == 0).unwrap_or(ifname.len());
        let name = String::from_utf8_lossy(&ifname[..end]).to_string();
        Ok(Self { name, fd })
    }

    /// Lee un paquete IP puro desde el TUN (eliminando la cabecera PI de 4 bytes en macOS).
    pub fn read_packet(&self, buf: &mut [u8]) -> Option<Vec<u8>> {
        let n = unsafe { libc::read(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n <= 0 {
            return None;
        }
        let n = n as usize;
        #[cfg(target_os = "macos")]
        {
            if n <= 4 {
                return None;
            }
            Some(buf[4..n].to_vec())
        }
        #[cfg(target_os = "linux")]
        {
            Some(buf[..n].to_vec())
        }
    }

    /// Escribe un paquete IP en el TUN (anteponiendo el encabezado PI de 4 bytes en macOS).
    pub fn write_packet(&self, pkt: &[u8]) -> bool {
        if pkt.is_empty() {
            return false;
        }
        #[cfg(target_os = "macos")]
        {
            let af: u32 = if (pkt[0] >> 4) == 6 { 30 } else { 2 }; // AF_INET6=30, AF_INET=2
            let mut framed = Vec::with_capacity(4 + pkt.len());
            framed.extend_from_slice(&af.to_be_bytes());
            framed.extend_from_slice(pkt);
            let n = unsafe {
                libc::write(self.fd, framed.as_ptr() as *const libc::c_void, framed.len())
            };
            return n == framed.len() as isize;
        }
        #[cfg(target_os = "linux")]
        {
            let n = unsafe { libc::write(self.fd, pkt.as_ptr() as *const libc::c_void, pkt.len()) };
            n == pkt.len() as isize
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl Drop for UnixTun {
    fn drop(&mut self) {
        if self.fd >= 0 {
            unsafe { libc::close(self.fd) };
            self.fd = -1;
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn configure_unix_tun_routes(iface: &str, local_vip: &str) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        let st = Command::new("ip")
            .args(["addr", "replace", &format!("{local_vip}/24"), "dev", iface])
            .status()
            .map_err(|e| format!("ip addr error: {e}"))?;
        if !st.success() {
            return Err("ip addr replace falló (requiere sudo/CAP_NET_ADMIN)".to_string());
        }
        let _ = Command::new("ip").args(["link", "set", "dev", iface, "mtu", "1280", "up"]).status();
        let _ = Command::new("ip").args(["route", "replace", "10.0.0.0/24", "dev", iface]).status();
    }
    #[cfg(target_os = "macos")]
    {
        let st = Command::new("ifconfig")
            .args([iface, "inet", local_vip, local_vip, "netmask", "255.255.255.0", "mtu", "1280", "up"])
            .status()
            .map_err(|e| format!("ifconfig error: {e}"))?;
        if !st.success() {
            return Err("ifconfig falló (requiere sudo)".to_string());
        }
        let _ = Command::new("route").args(["-n", "add", "-net", "10.0.0.0/24", "-interface", iface]).status();
    }
    Ok(())
}

/// Instala una ruta de Subnet Router o Exit Node (`0.0.0.0/0` / LAN `192.168.1.0/24`) en la interfaz TUN.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn advertise_subnet_route(iface: &str, cidr: &str) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        let st = Command::new("ip")
            .args(["route", "replace", cidr, "dev", iface])
            .status()
            .map_err(|e| format!("ip route error: {e}"))?;
        if !st.success() {
            return Err(format!("No se pudo instalar ruta {cidr} en {iface}"));
        }
    }
    #[cfg(target_os = "macos")]
    {
        let st = Command::new("route")
            .args(["-n", "add", "-net", cidr, "-interface", iface])
            .status()
            .map_err(|e| format!("route error: {e}"))?;
        if !st.success() {
            return Err(format!("No se pudo instalar ruta {cidr} en {iface}"));
        }
    }
    Ok(())
}

/// Activa IP forwarding y NAT masquerading para operar este nodo como Exit Node en Linux/macOS.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn enable_exit_node_nat(wan_iface: &str, mesh_cidr: &str) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        let _ = Command::new("sysctl").args(["-w", "net.ipv4.ip_forward=1"]).status();
        let st = Command::new("iptables")
            .args(["-t", "nat", "-C", "POSTROUTING", "-s", mesh_cidr, "-o", wan_iface, "-j", "MASQUERADE"])
            .status();
        if !matches!(st, Ok(s) if s.success()) {
            let add = Command::new("iptables")
                .args(["-t", "nat", "-A", "POSTROUTING", "-s", mesh_cidr, "-o", wan_iface, "-j", "MASQUERADE"])
                .status()
                .map_err(|e| format!("iptables MASQUERADE error: {e}"))?;
            if !add.success() {
                return Err("iptables -t nat MASQUERADE falló (requiere root)".to_string());
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        let _ = Command::new("sysctl").args(["-w", "net.inet.ip.forwarding=1"]).status();
        let rule = format!("nat on {wan_iface} from {mesh_cidr} to any -> ({wan_iface})\n");
        let _ = Command::new("sh")
            .args(["-c", &format!("printf '{}' | pfctl -f - && pfctl -e", rule.trim_end())])
            .status();
    }
    Ok(())
}

/// Configura Split DNS (`~nexomesh`, `~mesh`) en `systemd-resolved` (Linux) o `/etc/resolver` + `scutil` (macOS).
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn configure_unix_split_dns(iface: &str, dns_server: &str) {
    #[cfg(target_os = "linux")]
    {
        let ok_res = Command::new("resolvectl").args(["dns", iface, dns_server]).status();
        if matches!(ok_res, Ok(s) if s.success()) {
            let _ = Command::new("resolvectl")
                .args(["domain", iface, "~nexomesh", "~mesh"])
                .status();
        } else if let Ok(orig) = std::fs::read_to_string("/etc/resolv.conf") {
            if !orig.contains("# NexoMesh SplitDNS") {
                let _ = std::fs::write("/etc/resolv.conf.nexomesh.bak", &orig);
                let patched = format!("nameserver {dns_server} # NexoMesh SplitDNS\n{orig}");
                let _ = std::fs::write("/etc/resolv.conf", patched);
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        let _ = std::fs::create_dir_all("/etc/resolver");
        let content = format!("nameserver {dns_server}\n");
        let _ = std::fs::write("/etc/resolver/nexomesh", &content);
        let _ = std::fs::write("/etc/resolver/mesh", &content);
        let _ = Command::new("killall").args(["-HUP", "mDNSResponder"]).status();
    }
}

/// Limpia la configuración Split DNS en Linux/macOS al apagar la VPN.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn restore_unix_split_dns(iface: &str) {
    #[cfg(target_os = "linux")]
    {
        let _ = Command::new("resolvectl").args(["revert", iface]).status();
        if let Ok(bak) = std::fs::read_to_string("/etc/resolv.conf.nexomesh.bak") {
            let _ = std::fs::write("/etc/resolv.conf", bak);
            let _ = std::fs::remove_file("/etc/resolv.conf.nexomesh.bak");
        }
    }
    #[cfg(target_os = "macos")]
    {
        let _ = iface;
        let _ = std::fs::remove_file("/etc/resolver/nexomesh");
        let _ = std::fs::remove_file("/etc/resolver/mesh");
        let _ = Command::new("killall").args(["-HUP", "mDNSResponder"]).status();
    }
}
