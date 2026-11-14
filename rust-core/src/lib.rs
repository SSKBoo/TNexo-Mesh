use jni::objects::{JClass, JString};
use jni::sys::{jboolean, jint, jlong, jstring};
use jni::JNIEnv;
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

static TUNNEL_ACTIVE: AtomicBool = AtomicBool::new(false);
static BUNKER_MODE: AtomicBool = AtomicBool::new(false);
static BLOCKED_PACKETS: AtomicU64 = AtomicU64::new(0);
static MAX_PPS_LIMIT: AtomicUsize = AtomicUsize::new(120);

fn parse_stun_mapped_endpoint(buf: &[u8]) -> Option<String> {
    if buf.len() < 20 {
        return None;
    }
    let msg_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let end = (20 + msg_len).min(buf.len());
    let mut idx = 20;
    while idx + 4 <= end {
        let attr_type = u16::from_be_bytes([buf[idx], buf[idx + 1]]);
        let attr_len = u16::from_be_bytes([buf[idx + 2], buf[idx + 3]]) as usize;
        let val_start = idx + 4;
        if val_start + attr_len > end {
            break;
        }
        // 0x0020 = XOR-MAPPED-ADDRESS, 0x0001 = MAPPED-ADDRESS
        if (attr_type == 0x0020 || attr_type == 0x0001) && attr_len >= 8 && buf[val_start + 1] == 0x01 {
            let raw_port = u16::from_be_bytes([buf[val_start + 2], buf[val_start + 3]]);
            let port = if attr_type == 0x0020 { raw_port ^ 0x2112 } else { raw_port };
            let ip = if attr_type == 0x0020 {
                Ipv4Addr::new(
                    buf[val_start + 4] ^ 0x21,
                    buf[val_start + 5] ^ 0x12,
                    buf[val_start + 6] ^ 0xA4,
                    buf[val_start + 7] ^ 0x42,
                )
            } else {
                Ipv4Addr::new(buf[val_start + 4], buf[val_start + 5], buf[val_start + 6], buf[val_start + 7])
            };
            return Some(format!("{ip}:{port}"));
        }
        let padded = (attr_len + 3) & !3;
        idx = val_start + padded;
    }
    None
}

#[no_mangle]
pub extern "system" fn Java_io_nexomesh_vpn_RustCoreBridge_startTunnel(
    mut env: JNIEnv,
    _class: JClass,
    tun_fd: jint,
    local_ip: JString,
    _stun_server: JString,
    _keepalive_sec: jint,
) -> jint {
    let _ip: String = env
        .get_string(&local_ip)
        .map(|s| s.into())
        .unwrap_or_else(|_| "10.0.0.1".to_string());

    if tun_fd < 0 {
        return -1;
    }

    let _noise_builder = snow::Builder::new(
        "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
            .parse()
            .expect("Noise pattern"),
    );

    TUNNEL_ACTIVE.store(true, Ordering::SeqCst);
    0
}

#[no_mangle]
pub extern "system" fn Java_io_nexomesh_vpn_RustCoreBridge_stopTunnel(
    _env: JNIEnv,
    _class: JClass,
) {
    TUNNEL_ACTIVE.store(false, Ordering::SeqCst);
}

#[no_mangle]
pub extern "system" fn Java_io_nexomesh_vpn_RustCoreBridge_discoverStunEndpoint(
    mut env: JNIEnv,
    _class: JClass,
    stun_server: JString,
) -> jstring {
    let server: String = env
        .get_string(&stun_server)
        .map(|s| s.into())
        .unwrap_or_else(|_| "stun.l.google.com:19302".to_string());

    let ipv4_target: Option<SocketAddr> = server
        .to_socket_addrs()
        .ok()
        .and_then(|mut it| it.find(|a| a.is_ipv4()));

    let result = match (ipv4_target, UdpSocket::bind("0.0.0.0:0")) {
        (Some(target), Ok(sock)) => {
            let _ = sock.set_read_timeout(Some(Duration::from_millis(1400)));
            let mut req = [0u8; 20];
            req[0] = 0x00;
            req[1] = 0x01; // Binding Request
            req[4..8].copy_from_slice(&[0x21, 0x12, 0xA4, 0x42]);
            req[8..20].copy_from_slice(b"NEXOMESHSTUN");
            if sock.send_to(&req, target).is_ok() {
                let mut buf = [0u8; 256];
                match sock.recv_from(&mut buf) {
                    Ok((len, _)) if len >= 20 => {
                        if let Some(mapped) = parse_stun_mapped_endpoint(&buf[..len]) {
                            format!("STUN OK · Endpoint {mapped} ({server})")
                        } else {
                            format!("STUN OK ({len} bytes desde {server})")
                        }
                    }
                    _ => format!("Sin respuesta UDP de {server}"),
                }
            } else {
                format!("Fallo envío UDP a {server}")
            }
        }
        (None, _) => format!("No se pudo resolver {server}"),
        (_, Err(e)) => format!("Error UDP: {e}"),
    };

    env.new_string(result)
        .expect("Couldn't create java string")
        .into_raw()
}

#[no_mangle]
pub extern "system" fn Java_io_nexomesh_vpn_RustCoreBridge_setDefensePolicy(
    _env: JNIEnv,
    _class: JClass,
    bunker_mode: jboolean,
    max_pps: jint,
) {
    BUNKER_MODE.store(bunker_mode != 0, Ordering::SeqCst);
    if max_pps > 0 {
        MAX_PPS_LIMIT.store(max_pps as usize, Ordering::SeqCst);
    }
}

#[no_mangle]
pub extern "system" fn Java_io_nexomesh_vpn_RustCoreBridge_getBlockedPacketsCount(
    _env: JNIEnv,
    _class: JClass,
) -> jlong {
    BLOCKED_PACKETS.load(Ordering::SeqCst) as jlong
}

#[no_mangle]
pub extern "system" fn Java_io_nexomesh_vpn_RustCoreBridge_inspectPacket(
    _env: JNIEnv,
    _class: JClass,
    payload_len: jint,
    dst_port: jint,
) -> jboolean {
    let blocked_port = matches!(dst_port, 22 | 23 | 445 | 3389 | 5555);
    let oversized = payload_len > 1500;
    let bunker_block = BUNKER_MODE.load(Ordering::SeqCst) && dst_port != 51820 && dst_port != 51821;
    if blocked_port || oversized || bunker_block {
        BLOCKED_PACKETS.fetch_add(1, Ordering::SeqCst);
        return 0;
    }
    1
}
