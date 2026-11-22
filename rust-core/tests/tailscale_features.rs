use nexomesh_core::acl::{AclEngine, AclRule, Action, Proto};
use nexomesh_core::keys::dual_stack_ips_from_pubkey;
use nexomesh_core::magic_dns::MagicDns;
use nexomesh_core::nat::{
    bind_birthday_sockets, nat_pmp_udp_map_request, parse_nat_pmp_map_response,
    upnp_ssdp_discover_packet,
};
use nexomesh_core::routing::RoutingTable;
use std::net::{Ipv4Addr, Ipv6Addr};

#[test]
fn magic_dns_resolves_mesh_names_and_splits_external() {
    let mut dns = MagicDns::new();
    let v4 = Ipv4Addr::new(10, 0, 0, 2);
    let v6: Ipv6Addr = "fd7a:115c:a1e0::2".parse().unwrap();
    dns.register("laptop-pc", v4, Some(v6));

    assert_eq!(dns.resolve_v4("laptop-pc"), Some(v4));
    assert_eq!(dns.resolve_v4("laptop-pc.mesh."), Some(v4));
    assert_eq!(dns.resolve_v6("laptop-pc.mesh"), Some(v6));
    assert_eq!(dns.resolve_v4("google.com"), None);

    // Construir petición DNS RFC 1035 para "laptop-pc.mesh" (A=1)
    let mut query = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    query.push(9);
    query.extend_from_slice(b"laptop-pc");
    query.push(4);
    query.extend_from_slice(b"mesh");
    query.push(0);
    query.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
    query.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN

    let resp = dns.handle_dns_query(&query).expect("debe responder MagicDNS");
    assert_eq!(&resp[0..2], &[0x12, 0x34]);
    assert_eq!(&resp[resp.len() - 4..], &[10, 0, 0, 2]);
}

#[test]
fn cidr_subnet_router_and_exit_node_longest_prefix_match() {
    let mut table = RoutingTable::new();
    table.advertise_subnet("0.0.0.0/0", "exit-vps", true);
    table.advertise_subnet("192.168.1.0/24", "home-lan", false);
    table.advertise_subnet("10.0.0.0/24", "mesh-core", false);

    assert_eq!(table.route("192.168.1.50").as_deref(), Some("home-lan"));
    assert_eq!(table.route("10.0.0.3").as_deref(), Some("mesh-core"));
    assert_eq!(table.route("8.8.8.8").as_deref(), Some("exit-vps"));
}

#[test]
fn acl_engine_enforces_port_and_subnet_rules() {
    let mut acl = AclEngine::new(Action::Deny);
    acl.add_rule(AclRule {
        action: Action::Allow,
        src_cidr: "10.0.0.0/24".into(),
        dst_cidr: "10.0.0.1/32".into(),
        proto: Proto::Udp,
        dst_port: Some(19132),
    });
    acl.add_rule(AclRule {
        action: Action::Deny,
        src_cidr: "10.0.0.0/24".into(),
        dst_cidr: "10.0.0.1/32".into(),
        proto: Proto::Tcp,
        dst_port: Some(22),
    });

    let src = Ipv4Addr::new(10, 0, 0, 5);
    let dst = Ipv4Addr::new(10, 0, 0, 1);
    assert_eq!(acl.evaluate(src, dst, 17, 19132), Action::Allow);
    assert_eq!(acl.evaluate(src, dst, 6, 22), Action::Deny);
    assert_eq!(acl.evaluate(src, dst, 6, 8080), Action::Deny);
}

#[test]
fn nat_birthday_sockets_and_pmp_upnp_packets() {
    let sockets = bind_birthday_sockets(8);
    assert_eq!(sockets.len(), 8);

    let req = nat_pmp_udp_map_request(51820, 51820, 3600);
    assert_eq!(req[0], 0);
    assert_eq!(req[1], 1);

    let mut fake_resp = [0u8; 16];
    fake_resp[0] = 0;
    fake_resp[1] = 0x81;
    fake_resp[8..10].copy_from_slice(&51820u16.to_be_bytes());
    fake_resp[10..12].copy_from_slice(&51820u16.to_be_bytes());
    fake_resp[12..16].copy_from_slice(&3600u32.to_be_bytes());
    assert_eq!(parse_nat_pmp_map_response(&fake_resp), Some((51820, 51820, 3600)));

    let ssdp = std::str::from_utf8(upnp_ssdp_discover_packet()).unwrap();
    assert!(ssdp.contains("InternetGatewayDevice:1"));
}

#[test]
fn dual_stack_ipv4_and_ipv6_ula_from_pubkey() {
    let (v4, v6) = dual_stack_ips_from_pubkey("XkKcWKIU2YEziA4EO7T178Btu5RDt6qiN8KH7VpChfU=");
    assert_eq!(v4.octets()[0..3], [10, 0, 0]);
    assert!(v4.octets()[3] >= 2);
    assert_eq!(&v6.octets()[0..6], &[0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0]);
}
