use nexomesh_core::acl::{AclEngine, AclRule, Action, IdentityAclEngine, IdentityAclRule, NodeIdentity, Proto};
use nexomesh_core::derp::DerpRegion;
use nexomesh_core::keys::dual_stack_ips_from_pubkey;
use nexomesh_core::magic_dns::{spawn_split_dns_server, MagicDns};
use nexomesh_core::nat::{
    bind_birthday_sockets, nat_pmp_udp_map_request, parse_nat_pmp_map_response,
    upnp_ssdp_discover_packet,
};
use nexomesh_core::netcheck::run_full_netcheck;
use nexomesh_core::routing::RoutingTable;
use nexomesh_core::ssh::{issue_mesh_ssh_ticket, verify_mesh_ssh_ticket};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, TcpListener, UdpSocket};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

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
    assert_eq!(v4.octets()[0], 100);
    assert!((64..=127).contains(&v4.octets()[1]));
    assert!((1..=254).contains(&v4.octets()[3]));
    assert_eq!(&v6.octets()[0..6], &[0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0]);
}

#[test]
fn netcheck_detects_captive_portal_mapping_variability_and_hairpinning() {
    // 1. Mock portal cautivo HTTP 302
    let captive_srv = TcpListener::bind("127.0.0.1:0").unwrap();
    let captive_port = captive_srv.local_addr().unwrap().port();
    std::thread::spawn(move || {
        if let Ok((mut s, _)) = captive_srv.accept() {
            let mut req = [0u8; 256];
            let _ = s.read(&mut req);
            let _ = s.write_all(
                b"HTTP/1.1 302 Found\r\nLocation: http://hotel.wifi/login\r\nContent-Length: 0\r\n\r\n",
            );
        }
    });

    // 2. Dos servidores STUN falsos devolviendo distintos puertos mapeados (simula Symmetric NAT)
    let spawn_stun = |mapped_port: u16| -> String {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 128];
            if let Ok((n, from)) = sock.recv_from(&mut buf) {
                if n >= 20 {
                    let mut resp = [0u8; 32];
                    resp[0] = 0x01;
                    resp[1] = 0x01;
                    resp[2..4].copy_from_slice(&12u16.to_be_bytes());
                    resp[4..20].copy_from_slice(&buf[4..20]);
                    resp[20..24].copy_from_slice(&[0x00, 0x20, 0x00, 0x08]);
                    resp[24] = 0x00;
                    resp[25] = 0x01;
                    let xp = mapped_port ^ 0x2112;
                    resp[26..28].copy_from_slice(&xp.to_be_bytes());
                    resp[28] = 127 ^ 0x21;
                    resp[29] = 0 ^ 0x12;
                    resp[30] = 0 ^ 0xA4;
                    resp[31] = 1 ^ 0x42;
                    let _ = sock.send_to(&resp, from);
                }
            }
        });
        addr.to_string()
    };

    let stun1 = spawn_stun(40001);
    let stun2 = spawn_stun(40002);
    let derp_tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let derp_port = derp_tcp.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let _ = derp_tcp.accept();
    });

    let mut regions = vec![DerpRegion {
        id: 7,
        name: "mx-central".into(),
        endpoint: format!("ws://127.0.0.1:{derp_port}/ws"),
        rtt_ms: u32::MAX,
    }];

    let report = run_full_netcheck(
        &stun1,
        Some(&stun2),
        None,
        Some(&format!("http://127.0.0.1:{captive_port}/generate_204")),
        &mut regions,
    );
    assert!(report.udp_v4);
    assert_eq!(report.mapping_varies_by_dest_ip, Some(true));
    assert_eq!(report.captive_portal.checked, true);
    assert_eq!(report.captive_portal.detected, true);
    assert_eq!(report.preferred_derp, Some(7));
    let json = report.to_json();
    assert!(json.contains("hotel.wifi/login"));
}

#[test]
fn identity_acl_groups_tags_and_keyless_mesh_ssh_ticket() {
    let mut engine = IdentityAclEngine::new(Action::Deny);
    engine.add_rule(IdentityAclRule {
        action: Action::Allow,
        src_selector: "group:dev".into(),
        dst_selector: "tag:server".into(),
        proto: Proto::Tcp,
        dst_port: Some(22),
        allow_ssh: true,
    });

    let dev = NodeIdentity {
        ip: Ipv4Addr::new(100, 64, 0, 2),
        user_id: "uriel@nexomesh.io".into(),
        groups: vec!["group:dev".into()],
        tags: vec![],
    };
    let guest = NodeIdentity {
        ip: Ipv4Addr::new(100, 64, 0, 9),
        user_id: "guest@ext.io".into(),
        groups: vec!["group:guest".into()],
        tags: vec![],
    };
    let prod_srv = NodeIdentity {
        ip: Ipv4Addr::new(100, 64, 1, 10),
        user_id: "infra@nexomesh.io".into(),
        groups: vec![],
        tags: vec!["tag:server".into()],
    };

    assert_eq!(engine.evaluate_flow(&dev, &prod_srv, 6, 22), Action::Allow);
    assert_eq!(engine.evaluate_flow(&guest, &prod_srv, 6, 22), Action::Deny);

    let ticket = issue_mesh_ssh_ticket("control-ssh-seed", &engine, &dev, &prod_srv, 300)
        .expect("group:dev debe poder emitir ticket SSH sin llaves hacia tag:server");
    assert!(verify_mesh_ssh_ticket(&ticket, Some("control-ssh-seed"), None));
    assert!(!verify_mesh_ssh_ticket(&ticket, Some("wrong-seed"), None));
    assert!(!verify_mesh_ssh_ticket(&ticket, Some("control-ssh-seed"), Some(ticket.expires_at_sec + 10)));

    assert!(issue_mesh_ssh_ticket("control-ssh-seed", &engine, &guest, &prod_srv, 300).is_err());
}

#[test]
fn magic_dns_nexomesh_and_split_dns_udp_server() {
    let mut dns = MagicDns::new();
    dns.register("nas-casa", Ipv4Addr::new(10, 0, 0, 9), None);
    assert_eq!(dns.resolve_v4("nas-casa.nexomesh"), Some(Ipv4Addr::new(10, 0, 0, 9)));

    // Upstream falso que responde 1.2.3.4 para cualquier dominio externo
    let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
    let up_addr = upstream.local_addr().unwrap();
    std::thread::spawn(move || {
        let mut buf = [0u8; 512];
        if let Ok((n, from)) = upstream.recv_from(&mut buf) {
            let mut resp = buf[..n].to_vec();
            resp[2] = 0x81;
            resp[3] = 0x80;
            let _ = upstream.send_to(&resp, from);
        }
    });

    let (dns_addr, running) =
        spawn_split_dns_server("127.0.0.1:0", &up_addr.to_string(), Arc::new(Mutex::new(dns)))
            .unwrap();

    // Consulta Split DNS local para nas-casa.nexomesh
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let mut q_mesh = vec![0xAA, 0xBB, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    q_mesh.push(8);
    q_mesh.extend_from_slice(b"nas-casa");
    q_mesh.push(8);
    q_mesh.extend_from_slice(b"nexomesh");
    q_mesh.push(0);
    q_mesh.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    client.send_to(&q_mesh, dns_addr).unwrap();
    let mut rbuf = [0u8; 512];
    let (rn, _) = client.recv_from(&mut rbuf).unwrap();
    assert_eq!(&rbuf[rn - 4..rn], &[10, 0, 0, 9]);

    // Consulta externa -> reenviada al upstream
    let mut q_ext = vec![0xCC, 0xDD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    q_ext.push(7);
    q_ext.extend_from_slice(b"example");
    q_ext.push(3);
    q_ext.extend_from_slice(b"com");
    q_ext.push(0);
    q_ext.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    client.send_to(&q_ext, dns_addr).unwrap();
    let (en, _) = client.recv_from(&mut rbuf).unwrap();
    assert_eq!(&rbuf[0..2], &[0xCC, 0xDD]);
    assert!(en >= q_ext.len());

    running.store(false, Ordering::Relaxed);
}
