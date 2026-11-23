use nexomesh_core::derp::{
    build_icmp_echo_request, build_nm2_routed_frame, probe_derp_regions,
    select_nearest_derp_region, try_build_icmp_echo_reply, DerpRegion, Node, NodeEvent, RouteKind,
};
use nexomesh_core::session;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::time::Duration;

#[test]
fn userspace_node_falls_back_to_relay_when_no_udp_peer() {
    let key_a = "NODE_A_KEY";
    let key_b = "NODE_B_KEY";
    // Las sesiones se registran por IP virtual: el frame NM1 lleva senderVip
    // y el receptor abre con esa clave (igual que en Android).
    session::ensure_session("10.0.0.2", key_a, key_b).unwrap();
    session::ensure_session("10.0.0.3", key_b, key_a).unwrap();

    let mut node = Node::bind("10.0.0.2", "10.0.0.3", 0).unwrap();
    let rx = node.enable_relay();

    // Sin peer UDP configurado: debe publicar el frame NM1 en el relay.
    let packet = [0x45u8, 0x00, 0x00, 0x14];
    node.send_packet(&packet).unwrap();
    let frame = rx.try_recv().expect("debe haber frame en el relay");
    assert_eq!(&frame[0..3], b"NM1");
    assert_eq!(frame[3] as usize, "10.0.0.2".len());
    assert!(!node.using_direct());

    // El otro extremo puede abrirlo usando el senderVip del frame.
    let sender_len = frame[3] as usize;
    let sender_vip = std::str::from_utf8(&frame[4..4 + sender_len]).unwrap();
    assert_eq!(sender_vip, "10.0.0.2");
    let opened = session::open(sender_vip, &frame[4 + sender_len..]).unwrap();
    assert_eq!(&opened[..], &packet);
}

#[test]
fn direct_udp_hello_and_icmp_echo_roundtrip() {
    let key_a = "DIRECT_KEY_A";
    let key_b = "DIRECT_KEY_B";
    session::ensure_session("10.0.0.10", key_b, key_a).unwrap();
    session::ensure_session("10.0.0.11", key_a, key_b).unwrap();

    let mut node_a = Node::bind("10.0.0.10", "10.0.0.11", 0).unwrap();
    let mut node_b = Node::bind("10.0.0.11", "10.0.0.10", 0).unwrap();

    let addr_b: SocketAddr = format!("127.0.0.1:{}", node_b.local_port().unwrap())
        .parse()
        .unwrap();
    node_a.set_peer(addr_b);
    node_a.send_hello("node-a").unwrap();

    // B recibe NM_HELLO y responde NM_ACK aprendiendo el endpoint de A
    match node_b.poll_udp_once().unwrap() {
        Some(NodeEvent::Hello { vip, .. }) => assert_eq!(vip, "10.0.0.10"),
        other => panic!("esperaba Hello en B, obtuve {other:?}"),
    }
    match node_a.poll_udp_once().unwrap() {
        Some(NodeEvent::Ack { vip, .. }) => assert_eq!(vip, "10.0.0.11"),
        other => panic!("esperaba Ack en A, obtuve {other:?}"),
    }
    assert!(node_a.using_direct());
    assert!(node_b.using_direct());

    // A envía ICMP Echo Request cifrado a B, B responde Echo Reply cifrado
    let req = build_icmp_echo_request("10.0.0.10", "10.0.0.11", 7).unwrap();
    node_a.send_packet(&req).unwrap();

    let rx_req = match node_b.poll_udp_once().unwrap() {
        Some(NodeEvent::Packet { sender_vip, packet }) => {
            assert_eq!(sender_vip, "10.0.0.10");
            packet
        }
        other => panic!("esperaba Packet en B, obtuve {other:?}"),
    };
    let reply = try_build_icmp_echo_reply(&rx_req, "10.0.0.11").expect("ICMP Echo Reply válido");
    node_b.send_packet(&reply).unwrap();

    match node_a.poll_udp_once().unwrap() {
        Some(NodeEvent::Packet { sender_vip, packet }) => {
            assert_eq!(sender_vip, "10.0.0.11");
            assert_eq!(packet[20], 0); // Echo Reply (type=0)
            assert_eq!(u16::from_be_bytes([packet[26], packet[27]]), 7);
        }
        other => panic!("esperaba Echo Reply en A, obtuve {other:?}"),
    }
}

#[test]
fn derp_region_selection_picks_lowest_rtt_and_nm2_frame_header() {
    let regions = vec![
        DerpRegion { id: 1, name: "iad".into(), endpoint: "wss://iad.example/ws".into(), rtt_ms: 95 },
        DerpRegion { id: 2, name: "dfw".into(), endpoint: "wss://dfw.example/ws".into(), rtt_ms: 28 },
        DerpRegion { id: 3, name: "down".into(), endpoint: "wss://down.example/ws".into(), rtt_ms: u32::MAX },
    ];
    let best = select_nearest_derp_region(&regions).unwrap();
    assert_eq!(best.id, 2);
    assert_eq!(best.name, "dfw");

    let dst = [0xABu8; 32];
    let nm1 = b"NM1\x0810.0.0.2PAYLOAD";
    let nm2 = build_nm2_routed_frame(&dst, nm1);
    assert_eq!(&nm2[0..3], b"NM2");
    assert_eq!(&nm2[3..35], &dst[..]);
    assert_eq!(&nm2[35..], nm1);
}

#[test]
fn disco_hot_upgrades_relay_to_direct_and_falls_back_when_stale() {
    session::ensure_session("10.0.0.20", "DISCO_B", "DISCO_A").unwrap();
    session::ensure_session("10.0.0.21", "DISCO_A", "DISCO_B").unwrap();

    let mut node_a = Node::bind("10.0.0.20", "10.0.0.21", 0).unwrap();
    let mut node_b = Node::bind("10.0.0.21", "10.0.0.20", 0).unwrap();
    let _rx_a = node_a.enable_relay();
    assert!(!node_a.using_direct());

    let addr_b: SocketAddr = format!("127.0.0.1:{}", node_b.local_port().unwrap())
        .parse()
        .unwrap();
    node_a.set_peer(addr_b);
    node_a.send_disco_ping(999).unwrap();

    match node_b.poll_udp_once().unwrap() {
        Some(NodeEvent::DiscoPing { vip, tx_id, .. }) => {
            assert_eq!(vip, "10.0.0.20");
            assert_eq!(tx_id, 999);
        }
        other => panic!("esperaba DiscoPing en B, obtuve {other:?}"),
    }
    match node_a.poll_udp_once().unwrap() {
        Some(NodeEvent::DiscoPong { vip, tx_id, .. }) => {
            assert_eq!(vip, "10.0.0.21");
            assert_eq!(tx_id, 999);
        }
        other => panic!("esperaba DiscoPong en A, obtuve {other:?}"),
    }
    assert!(node_a.using_direct());
    assert!(node_a.last_disco_rtt_ms().is_some());

    // Al expirar el enlace directo vuelve automáticamente al relay DERP
    std::thread::sleep(Duration::from_millis(15));
    assert!(node_a.fallback_to_relay_if_stale(Duration::from_millis(5)));
    assert!(!node_a.using_direct());
}

#[test]
fn symmetric_nat_probe_sprays_birthday_sockets() {
    let node_a = Node::bind("10.0.0.30", "10.0.0.31", 0).unwrap();
    let node_b = Node::bind("10.0.0.31", "10.0.0.30", 0).unwrap();
    let port_b = node_b.local_port().unwrap();
    let sent = node_a.probe_symmetric_nat(Ipv4Addr::LOCALHOST, port_b, 1, 77);
    assert_eq!(sent, 32);
}

#[test]
fn magicsock_probes_candidates_and_selects_lowest_rtt_route() {
    let mut node_a = Node::bind("10.0.0.40", "10.0.0.41", 0).unwrap();
    let mut node_b = Node::bind("10.0.0.41", "10.0.0.40", 0).unwrap();

    let dead_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let live_addr: SocketAddr = format!("127.0.0.1:{}", node_b.local_port().unwrap()).parse().unwrap();
    node_a.set_peer(dead_addr);
    node_a.add_candidate(dead_addr, RouteKind::StunPublic);
    node_a.add_candidate(live_addr, RouteKind::Lan);

    let probed = node_a.probe_candidates();
    assert_eq!(probed, 2);

    // B recibe NM_DISCO_PING en su socket real y responde NM_DISCO_PONG
    match node_b.poll_udp_once().unwrap() {
        Some(NodeEvent::DiscoPing { vip, .. }) => assert_eq!(vip, "10.0.0.40"),
        other => panic!("esperaba DiscoPing en B, obtuve {other:?}"),
    }
    match node_a.poll_udp_once().unwrap() {
        Some(NodeEvent::DiscoPong { vip, from, .. }) => {
            assert_eq!(vip, "10.0.0.41");
            assert_eq!(from, live_addr);
        }
        other => panic!("esperaba DiscoPong en A, obtuve {other:?}"),
    }
    assert_eq!(node_a.peer_addr(), Some(live_addr), "magicsock debe promover la ruta directa viva");
    assert!(node_a.using_direct());
}

#[test]
fn automatic_tick_triggers_pfs_rekey_and_continues_encrypted_traffic() {
    session::ensure_session("10.0.0.50", "AUTO_B", "AUTO_A").unwrap();
    session::ensure_session("10.0.0.51", "AUTO_A", "AUTO_B").unwrap();

    let mut node_a = Node::bind("10.0.0.50", "10.0.0.51", 0).unwrap();
    let mut node_b = Node::bind("10.0.0.51", "10.0.0.50", 0).unwrap();
    let addr_a: SocketAddr = format!("127.0.0.1:{}", node_a.local_port().unwrap()).parse().unwrap();
    let addr_b: SocketAddr = format!("127.0.0.1:{}", node_b.local_port().unwrap()).parse().unwrap();
    node_a.set_peer(addr_b);
    node_b.set_peer(addr_a);

    // Programar rekey inmediato en el par "10.0.0.51" de A y dejar que tick() lo ejecute automáticamente
    session::schedule_rekey_now("10.0.0.51");
    assert!(session::needs_rekey("10.0.0.51"));
    node_a.tick();

    // B recibe DiscoPing y luego NM_REKEY_INIT -> rota y responde NM_REKEY_ACK
    loop {
        match node_b.poll_udp_once().unwrap() {
            Some(NodeEvent::Rekeyed { vip }) => {
                assert_eq!(vip, "10.0.0.50");
                break;
            }
            Some(NodeEvent::DiscoPing { .. }) | Some(NodeEvent::DiscoPong { .. }) => continue,
            other => panic!("esperaba Rekeyed en B, obtuve {other:?}"),
        }
    }
    // A recibe NM_REKEY_ACK y completa finish_pfs_rekey
    loop {
        match node_a.poll_udp_once().unwrap() {
            Some(NodeEvent::Rekeyed { vip }) => {
                assert_eq!(vip, "10.0.0.51");
                break;
            }
            Some(NodeEvent::DiscoPing { .. }) | Some(NodeEvent::DiscoPong { .. }) => continue,
            other => panic!("esperaba Rekeyed en A, obtuve {other:?}"),
        }
    }
    assert!(!session::needs_rekey("10.0.0.51"), "después de rotar, el contador y timer se reinician");

    // Verificar que el tráfico IP cifrado funciona con la nueva clave PFS
    let pkt = build_icmp_echo_request("10.0.0.50", "10.0.0.51", 42).unwrap();
    node_a.send_packet(&pkt).unwrap();
    loop {
        match node_b.poll_udp_once().unwrap() {
            Some(NodeEvent::Packet { sender_vip, packet }) => {
                assert_eq!(sender_vip, "10.0.0.50");
                assert_eq!(packet, pkt);
                break;
            }
            Some(NodeEvent::DiscoPong { .. }) | Some(NodeEvent::DiscoPing { .. }) => continue,
            other => panic!("esperaba Packet cifrado post-rekey en B, obtuve {other:?}"),
        }
    }
}

#[test]
fn derp_region_tcp_prober_selects_reachable_lowest_rtt() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let live_port = listener.local_addr().unwrap().port();
    let _accept_bg = std::thread::spawn(move || {
        let _ = listener.accept();
    });

    let mut regions = vec![
        DerpRegion { id: 1, name: "dead".into(), endpoint: "ws://127.0.0.1:1/ws".into(), rtt_ms: 0 },
        DerpRegion { id: 2, name: "live".into(), endpoint: format!("ws://127.0.0.1:{live_port}/ws"), rtt_ms: 999 },
    ];
    probe_derp_regions(&mut regions);
    let best = select_nearest_derp_region(&regions).expect("debe elegir región viva");
    assert_eq!(best.id, 2);
}

#[test]
fn noise_ik_1rtt_initial_handshake_and_netcheck_report() {
    session::ensure_session("10.0.0.61", "NOISE_A", "NOISE_B").unwrap();
    session::ensure_session("10.0.0.60", "NOISE_B", "NOISE_A").unwrap();

    let mut node_a = Node::bind("10.0.0.60", "10.0.0.61", 0).unwrap();
    let mut node_b = Node::bind("10.0.0.61", "10.0.0.60", 0).unwrap();
    let addr_a: SocketAddr = format!("127.0.0.1:{}", node_a.local_port().unwrap()).parse().unwrap();
    let addr_b: SocketAddr = format!("127.0.0.1:{}", node_b.local_port().unwrap()).parse().unwrap();
    node_a.set_peer(addr_b);
    node_b.set_peer(addr_a);

    // 1-RTT Noise IKpsk2 inicial disparado automáticamente por start_noise_ik_handshake()
    node_a.start_noise_ik_handshake().unwrap();
    match node_b.poll_udp_once().unwrap() {
        Some(NodeEvent::Rekeyed { vip }) => assert_eq!(vip, "10.0.0.60"),
        other => panic!("esperaba Noise IK responder en B, obtuve {other:?}"),
    }
    match node_a.poll_udp_once().unwrap() {
        Some(NodeEvent::Rekeyed { vip }) => assert_eq!(vip, "10.0.0.61"),
        other => panic!("esperaba Noise IK initiator en A, obtuve {other:?}"),
    }
    assert!(session::is_noise_ik_established("10.0.0.61"));
    assert!(session::is_noise_ik_established("10.0.0.60"));

    // Tráfico IP cifrado bajo el transporte Noise IKpsk2 (frame v4)
    let pkt = build_icmp_echo_request("10.0.0.60", "10.0.0.61", 88).unwrap();
    let frame = node_a.build_nm1_frame(&pkt).unwrap();
    let vip_len = frame[3] as usize;
    assert_eq!(frame[4 + vip_len], 0x04, "debe usar Noise_IKpsk2 transport frame v4");
    node_a.send_packet(&pkt).unwrap();
    for _ in 0..40 {
        match node_b.poll_udp_once().unwrap() {
            Some(NodeEvent::Packet { sender_vip, packet }) => {
                assert_eq!(sender_vip, "10.0.0.60");
                assert_eq!(packet, pkt);
                break;
            }
            Some(NodeEvent::DiscoPing { .. }) => continue,
            other => panic!("esperaba Packet Noise IK en B, obtuve {other:?}"),
        }
    }

    // Diagnóstico netcheck JSON + socket rebinding
    let report = node_a.netcheck_json(&[DerpRegion {
        id: 1,
        name: "na".into(),
        endpoint: "wss://na.example/ws".into(),
        rtt_ms: 22,
    }]);
    assert!(report.contains("\"noise_ik_1rtt\":true"));
    assert!(report.contains("\"mode\":\"direct\""));
    let old_port = node_a.local_port().unwrap();
    let new_port = node_a.rebind_udp().unwrap();
    assert_ne!(new_port, old_port);
}
