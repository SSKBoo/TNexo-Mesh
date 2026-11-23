pub mod crypto;
pub mod keys;
pub mod noise;
pub mod session;
pub mod derp;
pub mod ws_client;
pub mod tunnel;
pub mod routing;
pub mod magic_dns;
pub mod acl;
pub mod nat;
pub mod stun;
pub mod turn;
pub mod signaling;
pub mod peer;
pub mod mesh;

use jni::objects::{JClass, JString};
use jni::sys::{jboolean, jint, jlong, jstring};
use jni::JNIEnv;
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use std::sync::{Mutex, OnceLock};

static MAGIC_DNS: OnceLock<Mutex<magic_dns::MagicDns>> = OnceLock::new();
static ACL_ENGINE: OnceLock<Mutex<acl::AclEngine>> = OnceLock::new();

fn magic_dns() -> &'static Mutex<magic_dns::MagicDns> {
    MAGIC_DNS.get_or_init(|| Mutex::new(magic_dns::MagicDns::new()))
}

fn acl_engine() -> &'static Mutex<acl::AclEngine> {
    ACL_ENGINE.get_or_init(|| Mutex::new(acl::AclEngine::new(acl::Action::Allow)))
}

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
                            format!("STUN OK Â· Endpoint {mapped} ({server})")
                        } else {
                            format!("STUN OK ({len} bytes desde {server})")
                        }
                    }
                    _ => format!("Sin respuesta UDP de {server}"),
                }
            } else {
                format!("Fallo envÃ­o UDP a {server}")
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


// ---------------------------------------------------------------------------
// FFI C ABI (nexomesh_* symbols)
// ---------------------------------------------------------------------------
use std::ffi::{c_char, CString};

static LAST_STATUS: std::sync::Mutex<Option<CString>> = std::sync::Mutex::new(None);

fn status_json() -> String {
    format!(
        "{{\"tunnel_active\":{},\"bunker_mode\":{},\"blocked_packets\":{}}}",
        TUNNEL_ACTIVE.load(Ordering::SeqCst),
        BUNKER_MODE.load(Ordering::SeqCst),
        BLOCKED_PACKETS.load(Ordering::SeqCst),
    )
}

#[no_mangle]
pub extern "C" fn nexomesh_init() {}

#[no_mangle]
pub extern "C" fn nexomesh_connect(_pubkey: *const c_char, _endpoint: *const c_char) -> i32 { 0 }

#[no_mangle]
pub extern "C" fn nexomesh_disconnect() {}

#[no_mangle]
pub extern "C" fn nexomesh_status_json() -> *const c_char {
    let mut guard = LAST_STATUS.lock().unwrap();
    *guard = CString::new(status_json()).ok();
    guard.as_ref().map(|s| s.as_ptr()).unwrap_or(std::ptr::null())
}

#[no_mangle]
pub extern "C" fn nexomesh_send_file(_peer: *const c_char, _path: *const c_char) -> i32 { 0 }

#[no_mangle]
pub extern "C" fn nexomesh_on_event(_cb: extern "C" fn(*const c_char)) {}

// ---------------------------------------------------------------------------
// JNI: cifrado del data plane del tunel (session.rs)
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "system" fn Java_io_nexomesh_vpn_RustCoreBridge_initSession(
    mut env: JNIEnv,
    _class: JClass,
    peer_id: JString,
    local_key: JString,
    peer_key: JString,
) -> jboolean {
    let pid: String = env.get_string(&peer_id).map(|s| s.into()).unwrap_or_default();
    let lk: String = env.get_string(&local_key).map(|s| s.into()).unwrap_or_default();
    let pk: String = env.get_string(&peer_key).map(|s| s.into()).unwrap_or_default();
    match session::ensure_session(&pid, &lk, &pk) {
        Ok(_) => 1,
        Err(_) => 0,
    }
}

/// Devuelve el frame cifrado o un array vacio si falla.
#[no_mangle]
pub extern "system" fn Java_io_nexomesh_vpn_RustCoreBridge_sealPacket<'a>(
    mut env: JNIEnv<'a>,
    _class: JClass<'a>,
    peer_id: JString,
    plaintext: jni::objects::JByteArray,
) -> jni::objects::JByteArray<'a> {
    let empty = env.byte_array_from_slice(&[]).unwrap_or(jni::objects::JByteArray::default());
    let pid: String = match env.get_string(&peer_id) { Ok(s) => s.into(), Err(_) => return empty };
    let data: Vec<u8> = match env.convert_byte_array(plaintext) { Ok(v) => v, Err(_) => return empty };
    match session::seal(&pid, &data) {
        Ok(out) => env.byte_array_from_slice(&out).unwrap_or(empty),
        Err(_) => empty,
    }
}

#[no_mangle]
pub extern "system" fn Java_io_nexomesh_vpn_RustCoreBridge_openPacket<'a>(
    mut env: JNIEnv<'a>,
    _class: JClass<'a>,
    peer_id: JString,
    frame: jni::objects::JByteArray,
) -> jni::objects::JByteArray<'a> {
    let empty = env.byte_array_from_slice(&[]).unwrap_or(jni::objects::JByteArray::default());
    let pid: String = match env.get_string(&peer_id) { Ok(s) => s.into(), Err(_) => return empty };
    let data: Vec<u8> = match env.convert_byte_array(frame) { Ok(v) => v, Err(_) => return empty };
    match session::open(&pid, &data) {
        Ok(out) => env.byte_array_from_slice(&out).unwrap_or(empty),
        Err(_) => empty,
    }
}

#[no_mangle]
pub extern "system" fn Java_io_nexomesh_vpn_RustCoreBridge_getSigningPublicKey(
    mut env: JNIEnv,
    _class: JClass,
    seed: JString,
) -> jstring {
    let s: String = env.get_string(&seed).map(|v| v.into()).unwrap_or_default();
    let pub_b64 = keys::signing_public_key_b64(&s);
    env.new_string(pub_b64)
        .expect("Couldn't create java string")
        .into_raw()
}

#[no_mangle]
pub extern "system" fn Java_io_nexomesh_vpn_RustCoreBridge_signChallenge(
    mut env: JNIEnv,
    _class: JClass,
    seed: JString,
    nonce: JString,
) -> jstring {
    let s: String = env.get_string(&seed).map(|v| v.into()).unwrap_or_default();
    let n: String = env.get_string(&nonce).map(|v| v.into()).unwrap_or_default();
    let (_, sig_b64) = keys::sign_challenge_b64(&s, &n);
    env.new_string(sig_b64)
        .expect("Couldn't create java string")
        .into_raw()
}

// ---------------------------------------------------------------------------
// JNI: MagicDNS embebido + Motor de politicas ACL
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "system" fn Java_io_nexomesh_vpn_RustCoreBridge_registerMagicDnsHost(
    mut env: JNIEnv,
    _class: JClass,
    name: JString,
    ipv4: JString,
) {
    let host: String = env.get_string(&name).map(|v| v.into()).unwrap_or_default();
    let ip_str: String = env.get_string(&ipv4).map(|v| v.into()).unwrap_or_default();
    if let Ok(v4) = ip_str.parse::<Ipv4Addr>() {
        if !host.trim().is_empty() {
            magic_dns().lock().unwrap().register(&host, v4, None);
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_io_nexomesh_vpn_RustCoreBridge_resolveMagicDnsPacket<'a>(
    env: JNIEnv<'a>,
    _class: JClass<'a>,
    query: jni::objects::JByteArray,
) -> jni::objects::JByteArray<'a> {
    let empty = env.byte_array_from_slice(&[]).unwrap_or(jni::objects::JByteArray::default());
    let req: Vec<u8> = match env.convert_byte_array(query) {
        Ok(v) => v,
        Err(_) => return empty,
    };
    let guard = magic_dns().lock().unwrap();
    match guard.handle_dns_query(&req) {
        Some(resp) => env.byte_array_from_slice(&resp).unwrap_or(empty),
        None => empty,
    }
}

#[no_mangle]
pub extern "system" fn Java_io_nexomesh_vpn_RustCoreBridge_addAclRule(
    mut env: JNIEnv,
    _class: JClass,
    allow: jboolean,
    src_cidr: JString,
    dst_cidr: JString,
    ip_proto: jint,
    dst_port: jint,
) {
    let src: String = env.get_string(&src_cidr).map(|v| v.into()).unwrap_or_else(|_| "0.0.0.0/0".into());
    let dst: String = env.get_string(&dst_cidr).map(|v| v.into()).unwrap_or_else(|_| "0.0.0.0/0".into());
    let proto = if ip_proto <= 0 {
        acl::Proto::Any
    } else {
        acl::Proto::from_ip_proto(ip_proto as u8)
    };
    let port = if dst_port > 0 && dst_port <= 65535 {
        Some(dst_port as u16)
    } else {
        None
    };
    acl_engine().lock().unwrap().add_rule(acl::AclRule {
        action: if allow != 0 { acl::Action::Allow } else { acl::Action::Deny },
        src_cidr: src,
        dst_cidr: dst,
        proto,
        dst_port: port,
    });
}

#[no_mangle]
pub extern "system" fn Java_io_nexomesh_vpn_RustCoreBridge_checkAclPacket(
    mut env: JNIEnv,
    _class: JClass,
    src_ip: JString,
    dst_ip: JString,
    ip_proto: jint,
    dst_port: jint,
) -> jboolean {
    let s_str: String = env.get_string(&src_ip).map(|v| v.into()).unwrap_or_default();
    let d_str: String = env.get_string(&dst_ip).map(|v| v.into()).unwrap_or_default();
    let (Ok(src), Ok(dst)) = (s_str.parse::<Ipv4Addr>(), d_str.parse::<Ipv4Addr>()) else {
        return 1;
    };
    let port = dst_port.clamp(0, 65535) as u16;
    let action = acl_engine()
        .lock()
        .unwrap()
        .evaluate(src, dst, ip_proto.clamp(0, 255) as u8, port);
    if action == acl::Action::Allow { 1 } else { 0 }
}
