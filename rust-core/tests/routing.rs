use nexomesh_core::routing::{RoutingTable, route};

#[test]
fn longest_prefix() {
    let mut t = RoutingTable::new();
    t.add("10.0.0.", "peer1", false);
    t.add("10.0.", "peer2", false);
    assert_eq!(t.route("10.0.0.5").unwrap(), "peer1");
    assert_eq!(route("10.0.0.5", &t).unwrap(), "peer1");
}
