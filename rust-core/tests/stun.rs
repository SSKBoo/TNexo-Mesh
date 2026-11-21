use nexomesh_core::stun::stun_binding_request;

#[test]
fn stun_request_len() {
    let r = stun_binding_request();
    assert_eq!(r.len(), 20);
}
