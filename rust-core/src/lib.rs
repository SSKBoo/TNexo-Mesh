use jni::objects::{JClass, JString};
use jni::sys::{jint, jstring};
use jni::JNIEnv;
use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

static TUNNEL_ACTIVE: AtomicBool = AtomicBool::new(false);

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

    // Inicializa estado Noise IKpsk2 con snow
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

    let result = match UdpSocket::bind("0.0.0.0:0") {
        Ok(sock) => {
            let _ = sock.set_read_timeout(Some(Duration::from_millis(1200)));
            // RFC 5389 STUN Binding Request mínimo (20 bytes)
            let mut req = [0u8; 20];
            req[0] = 0x00;
            req[1] = 0x01; // Binding Request
            req[4..8].copy_from_slice(&[0x21, 0x12, 0xA4, 0x42]); // Magic cookie
            req[8..20].copy_from_slice(b"NEXOMESHSTUN");
            if sock.send_to(&req, &server).is_ok() {
                let mut buf = [0u8; 256];
                match sock.recv_from(&mut buf) {
                    Ok((len, _)) if len >= 20 => format!("STUN OK ({len} bytes desde {server})"),
                    _ => format!("Sin respuesta UDP de {server}"),
                }
            } else {
                format!("No se pudo resolver {server}")
            }
        }
        Err(e) => format!("Error UDP: {e}"),
    };

    env.new_string(result)
        .expect("Couldn't create java string")
        .into_raw()
}
