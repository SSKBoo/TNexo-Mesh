//! Pruebas E2E reales de topologías NAT (Cone NAT, Doble NAT, NAT Simétrico),
//! pérdida de paquetes y conmutación en caliente DERP <-> P2P directo.

use nexomesh_core::derp::{build_icmp_echo_request, Node, NodeEvent};
use nexomesh_core::session;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

struct NatProxyHandle {
    lan_addr: SocketAddr,
    ext_addr: SocketAddr,
    enabled: Arc<AtomicBool>,
    running: Arc<AtomicBool>,
}

impl Drop for NatProxyHandle {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

fn spawn_nat_router(
    lan_client: SocketAddr,
    wan_peer_slot: Arc<std::sync::Mutex<Option<SocketAddr>>>,
    drop_every_n: usize,
) -> NatProxyHandle {
    let lan_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let wan_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    lan_sock.set_read_timeout(Some(Duration::from_millis(15))).unwrap();
    wan_sock.set_read_timeout(Some(Duration::from_millis(15))).unwrap();

    let lan_addr = lan_sock.local_addr().unwrap();
    let ext_addr = wan_sock.local_addr().unwrap();
    let wan_clone = wan_sock.try_clone().unwrap();
    let lan_clone = lan_sock.try_clone().unwrap();
    let enabled = Arc::new(AtomicBool::new(true));
    let running = Arc::new(AtomicBool::new(true));
    let en_out = Arc::clone(&enabled);
    let en_in = Arc::clone(&enabled);
    let run_out = Arc::clone(&running);
    let run_in = Arc::clone(&running);
    let counter = Arc::new(AtomicUsize::new(0));
    let counter_in = Arc::clone(&counter);

    thread::spawn(move || {
        let mut buf = [0u8; 4200];
        while run_out.load(Ordering::Relaxed) {
            if let Ok((n, _)) = lan_sock.recv_from(&mut buf) {
                if !en_out.load(Ordering::Relaxed) {
                    continue;
                }
                let idx = counter.fetch_add(1, Ordering::Relaxed) + 1;
                if drop_every_n > 0 && idx % drop_every_n == 0 {
                    continue;
                }
                if let Some(target) = *wan_peer_slot.lock().unwrap() {
                    let _ = wan_clone.send_to(&buf[..n], target);
                }
            }
        }
    });

    thread::spawn(move || {
        let mut buf = [0u8; 4200];
        while run_in.load(Ordering::Relaxed) {
            if let Ok((n, _)) = wan_sock.recv_from(&mut buf) {
                if !en_in.load(Ordering::Relaxed) {
                    continue;
                }
                let idx = counter_in.fetch_add(1, Ordering::Relaxed) + 1;
                if drop_every_n > 0 && idx % drop_every_n == 0 {
                    continue;
                }
                let _ = lan_clone.send_to(&buf[..n], lan_client);
            }
        }
    });

    NatProxyHandle {
        lan_addr,
        ext_addr,
        enabled,
        running,
    }
}

#[test]
fn e2e_double_cone_nat_with_packet_loss_and_derp_p2p_failover() {
    session::ensure_session("10.0.0.102", "NAT_A", "NAT_B").unwrap();
    session::ensure_session("10.0.0.101", "NAT_B", "NAT_A").unwrap();

    let mut node_a = Node::bind("10.0.0.101", "10.0.0.102", 0).unwrap();
    let mut node_b = Node::bind("10.0.0.102", "10.0.0.101", 0).unwrap();
    let rx_relay_a = node_a.enable_relay();
    let _rx_relay_b = node_b.enable_relay();

    let addr_a: SocketAddr = format!("127.0.0.1:{}", node_a.local_port().unwrap()).parse().unwrap();
    let addr_b: SocketAddr = format!("127.0.0.1:{}", node_b.local_port().unwrap()).parse().unwrap();

    let slot_a = Arc::new(std::sync::Mutex::new(None));
    let slot_b = Arc::new(std::sync::Mutex::new(None));
    let nat_a = spawn_nat_router(addr_a, Arc::clone(&slot_a), 5); // 20% packet loss en salto A
    let nat_b = spawn_nat_router(addr_b, Arc::clone(&slot_b), 0);
    *slot_a.lock().unwrap() = Some(nat_b.ext_addr);
    *slot_b.lock().unwrap() = Some(nat_a.ext_addr);

    // 1. Antes de hole punch: tráfico arranca vía DERP sin bloqueos
    let initial_pkt = build_icmp_echo_request("10.0.0.101", "10.0.0.102", 1).unwrap();
    node_a.send_packet(&initial_pkt).unwrap();
    let relay_frame = rx_relay_a.try_recv().expect("debe enrutar inicialmente por DERP");
    let (_svip, dec) = Node::parse_nm1_frame(&relay_frame).unwrap();
    assert_eq!(dec, initial_pkt);

    // 2. Promoción en caliente DERP -> UDP directo atravesando Doble NAT
    node_a.set_peer(nat_a.lan_addr);
    node_b.set_peer(nat_b.lan_addr);

    for i in 0..10u64 {
        let _ = node_a.send_disco_ping(100 + i);
        thread::sleep(Duration::from_millis(5));
        let _ = node_b.poll_udp_once();
        let _ = node_a.poll_udp_once();
    }
    assert!(node_a.using_direct(), "A debe promocionar a UDP directo atravesando Doble NAT");

    // 3. Enviar 15 paquetes con 20% pérdida simulada (anti-replay acepta saltos en secuencia)
    let mut delivered = 0usize;
    for seq in 10..25u16 {
        let pkt = build_icmp_echo_request("10.0.0.101", "10.0.0.102", seq).unwrap();
        node_a.send_packet(&pkt).unwrap();
        thread::sleep(Duration::from_millis(5));
        while let Ok(Some(ev)) = node_b.poll_udp_once() {
            if matches!(ev, NodeEvent::Packet { .. }) {
                delivered += 1;
            }
        }
    }
    assert!(delivered >= 6, "deben llegar paquetes válidos a pesar de la pérdida (recibidos={delivered})");

    // 4. Corte total del camino NAT -> degradación automática a DERP sin cortes
    nat_a.enabled.store(false, Ordering::Relaxed);
    nat_b.enabled.store(false, Ordering::Relaxed);
    thread::sleep(Duration::from_millis(20));
    assert!(node_a.fallback_to_relay_if_stale(Duration::from_millis(10)));
    assert!(!node_a.using_direct());

    let failover_pkt = build_icmp_echo_request("10.0.0.101", "10.0.0.102", 99).unwrap();
    node_a.send_packet(&failover_pkt).unwrap();
    assert!(rx_relay_a.try_recv().is_ok(), "tras caída del enlace NAT debe regresar a DERP sin cortes");
}

#[test]
fn e2e_symmetric_nat_birthday_paradox_probe_reaches_peer() {
    let node_a = Node::bind("10.0.0.111", "10.0.0.112", 0).unwrap();
    let mut node_b = Node::bind("10.0.0.112", "10.0.0.111", 0).unwrap();

    // NAT simétrico asignando puerto efímero diferente por cada datagrama saliente
    let sym_in = UdpSocket::bind("127.0.0.1:0").unwrap();
    let sym_port = sym_in.local_addr().unwrap().port();
    let target_b: SocketAddr = format!("127.0.0.1:{}", node_b.local_port().unwrap()).parse().unwrap();
    let running = Arc::new(AtomicBool::new(true));
    let running_bg = Arc::clone(&running);
    sym_in.set_read_timeout(Some(Duration::from_millis(20))).unwrap();

    thread::spawn(move || {
        let mut buf = [0u8; 512];
        while running_bg.load(Ordering::Relaxed) {
            if let Ok((n, _src)) = sym_in.recv_from(&mut buf) {
                if let Ok(eph) = UdpSocket::bind("127.0.0.1:0") {
                    let _ = eph.send_to(&buf[..n], target_b);
                }
            }
        }
    });

    let sprayed = node_a.probe_symmetric_nat(Ipv4Addr::LOCALHOST, sym_port, 1, 555);
    assert_eq!(sprayed, 32);

    let mut saw_disco = false;
    for _ in 0..25 {
        if let Ok(Some(NodeEvent::DiscoPing { tx_id, .. })) = node_b.poll_udp_once() {
            if tx_id == 555 {
                saw_disco = true;
                break;
            }
        }
        thread::sleep(Duration::from_millis(5));
    }
    running.store(false, Ordering::Relaxed);
    assert!(saw_disco, "las sondas Birthday Paradox deben alcanzar al par a través del NAT simétrico");
}
