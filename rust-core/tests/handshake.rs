use nexomesh_core::noise::NOISE_PATTERN;
use nexomesh_core::{
    nexomesh_configure_session, nexomesh_disconnect, nexomesh_init, nexomesh_netcheck_json,
    nexomesh_push_outbound_ip, nexomesh_rebind_network, nexomesh_status_json,
};
use std::ffi::{CStr, CString};

#[test]
fn pattern_name() {
    assert_eq!(NOISE_PATTERN, "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s");
}

#[test]
fn ios_c_ffi_runtime_pushes_packets_rebinds_and_reports_netcheck() {
    nexomesh_init();
    let lv = CString::new("10.0.0.2").unwrap();
    let pv = CString::new("10.0.0.1").unwrap();
    let lk = CString::new("IOS_KEY_A").unwrap();
    let pk = CString::new("IOS_KEY_B").unwrap();
    let ep = CString::new("127.0.0.1:59999").unwrap();

    assert_eq!(
        nexomesh_configure_session(lv.as_ptr(), pv.as_ptr(), lk.as_ptr(), pk.as_ptr(), ep.as_ptr()),
        0
    );
    let pkt = [0x45u8, 0x00, 0x00, 0x14];
    assert_eq!(nexomesh_push_outbound_ip(pkt.as_ptr(), pkt.len() as i32), 0);
    assert!(nexomesh_rebind_network() > 0);

    let status = unsafe { CStr::from_ptr(nexomesh_status_json()) }.to_str().unwrap();
    assert!(status.contains("\"tunnel_active\":true"));

    let netcheck = unsafe { CStr::from_ptr(nexomesh_netcheck_json()) }.to_str().unwrap();
    assert!(netcheck.contains("\"peer_vip\":\"10.0.0.1\""));

    nexomesh_disconnect();
}
