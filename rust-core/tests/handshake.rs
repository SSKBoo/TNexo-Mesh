use nexomesh_core::noise::NOISE_PATTERN;
use nexomesh_core::{
    nexomesh_configure_session, nexomesh_disconnect, nexomesh_init, nexomesh_netcheck_json,
    nexomesh_poll_inbound_ip, nexomesh_push_outbound_ip, nexomesh_rebind_network,
    nexomesh_status_json, session,
};
use nexomesh_core::derp::Node;
use std::ffi::{CStr, CString};
use std::net::SocketAddr;

#[test]
fn pattern_name() {
    assert_eq!(NOISE_PATTERN, "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s");
}

#[test]
fn ios_c_ffi_runtime_enforces_1rtt_pfs_rebinds_and_reports_netcheck() {
    nexomesh_init();
    session::ensure_noise_session("100.64.0.2", "IOS_KEY_B", "IOS_KEY_A").unwrap();
    let mut peer = Node::bind("100.64.0.1", "100.64.0.2", 0).unwrap();
    let peer_addr: SocketAddr = format!("127.0.0.1:{}", peer.local_port().unwrap()).parse().unwrap();

    let lv = CString::new("100.64.0.2").unwrap();
    let pv = CString::new("100.64.0.1").unwrap();
    let lk = CString::new("IOS_KEY_A").unwrap();
    let pk = CString::new("IOS_KEY_B").unwrap();
    let ep = CString::new(peer_addr.to_string()).unwrap();

    assert_eq!(
        nexomesh_configure_session(lv.as_ptr(), pv.as_ptr(), lk.as_ptr(), pk.as_ptr(), ep.as_ptr()),
        0
    );

    // Antes de completar el 1-RTT Noise_IKpsk2 no permite enviar tráfico estático
    let pkt = [0x45u8, 0x00, 0x00, 0x14];
    assert_eq!(nexomesh_push_outbound_ip(pkt.as_ptr(), pkt.len() as i32), -3);

    // El par responde NM_NOISE_1 -> NM_NOISE_2 y poll_inbound completa el handshake 1-RTT
    let _ = peer.poll_udp_once();
    let mut rx_buf = [0u8; 2048];
    let _ = nexomesh_poll_inbound_ip(rx_buf.as_mut_ptr(), rx_buf.len() as i32);

    assert_eq!(nexomesh_push_outbound_ip(pkt.as_ptr(), pkt.len() as i32), 0);
    assert!(nexomesh_rebind_network() > 0);

    let status = unsafe { CStr::from_ptr(nexomesh_status_json()) }.to_str().unwrap();
    assert!(status.contains("\"tunnel_active\":true"));

    let netcheck = unsafe { CStr::from_ptr(nexomesh_netcheck_json()) }.to_str().unwrap();
    assert!(netcheck.contains("\"peer_vip\":\"100.64.0.1\""));
    assert!(netcheck.contains("\"noise_ik_1rtt\":true"));

    nexomesh_disconnect();
}
