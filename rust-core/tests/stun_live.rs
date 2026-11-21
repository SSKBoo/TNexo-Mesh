use std::net::UdpSocket;
use nexomesh_core::stun::{stun_binding_request, parse_mapped_address};

#[test]
fn stun_binding_roundtrip_against_local_server() {
    if std::env::var("NEXOMESH_STUN_LIVE").is_err() {
        eprintln!("skip: set NEXOMESH_STUN_LIVE=1 and run backend/test/stun-server.mjs");
        return;
    }
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
    sock.send_to(&stun_binding_request(), "127.0.0.1:3478").unwrap();
    let mut buf = [0u8; 1024];
    let (n, _) = sock.recv_from(&mut buf).unwrap();
    assert_eq!(u16::from_be_bytes([buf[0], buf[1]]), 0x0101);
    let mapped = parse_mapped_address(&buf[..n]);
    assert!(mapped.is_some());
    eprintln!("mapped: {:?}", mapped);
}
