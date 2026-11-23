use nexomesh_core::derp::{
    build_icmp_echo_request, try_build_icmp_echo_reply, Node, NodeEvent,
};
use nexomesh_core::session;
use nexomesh_core::ws_client::{base64_decode, extract_json_str, WsClient, WsFrame};
use std::env;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage();
        return;
    }
    match args[1].as_str() {
        "keygen" => {
            let (sk, pk) = nexomesh_core::crypto::generate_keypair();
            println!("private={}", hex(&sk.to_bytes()));
            println!("public={}", hex(pk.as_bytes()));
        }
        "status" => println!("status ok"),
        "tunnel" => run_tunnel(&args[2..]),
        _ => print_usage(),
    }
}

fn print_usage() {
    println!(
        "nexomesh-cli: keygen | status | tunnel --local <vip> --peer <vip> [--port N] [--peer-addr ip:port] [--relay [ws://host:port/ws]] [--id nombre] [--ping]"
    );
}

fn arg(args: &[String], key: &str) -> Option<String> {
    args.iter()
        .position(|a| a == key)
        .and_then(|i| args.get(i + 1))
        .filter(|v| !v.starts_with("--"))
        .cloned()
}

fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|a| a == flag)
}

fn run_tunnel(args: &[String]) {
    let local = arg(args, "--local").unwrap_or_else(|| "10.0.0.2".to_string());
    let peer = arg(args, "--peer").unwrap_or_else(|| "10.0.0.1".to_string());
    let port: u16 = arg(args, "--port")
        .and_then(|v| v.parse().ok())
        .unwrap_or(51820);
    let node_id = arg(args, "--id").unwrap_or_else(|| format!("node-{local}"));
    let do_ping = has_flag(args, "--ping");

    let relay_url = arg(args, "--relay").or_else(|| {
        if has_flag(args, "--relay") {
            Some(
                env::var("NEXOMESH_RELAY_URL")
                    .unwrap_or_else(|_| "ws://127.0.0.1:8080/ws".to_string()),
            )
        } else {
            None
        }
    });

    // Sesión X25519 + ChaCha20-Poly1305 registrada bajo la IP virtual del par (`peer`)
    // para coincidir con seal(&peer) y open(sender_vip).
    let local_key = env::var("NEXOMESH_LOCAL_KEY").unwrap_or_else(|_| format!("key-{local}"));
    let peer_key = env::var("NEXOMESH_PEER_KEY").unwrap_or_else(|_| format!("key-{peer}"));
    if let Err(e) = session::ensure_session(&peer, &local_key, &peer_key) {
        eprintln!("[ERROR] sesión criptográfica: {e}");
        return;
    }

    let mut node = match Node::bind(&local, &peer, port) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("[ERROR] bind UDP :{port}: {e}");
            return;
        }
    };
    let (peer_sign_b64, _) = nexomesh_core::keys::sign_challenge_b64(&peer_key, "");
    if let Ok(pk_raw) = base64_decode(&peer_sign_b64) {
        if pk_raw.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&pk_raw);
            node.set_relay_target_signing_key(arr);
        }
    }

    if let Some(peer_addr_str) = arg(args, "--peer-addr") {
        match peer_addr_str.parse::<SocketAddr>() {
            Ok(addr) => node.set_peer(addr),
            Err(e) => {
                eprintln!("[ERROR] --peer-addr inválido '{peer_addr_str}': {e}");
                return;
            }
        }
    }

    let relay_rx = if relay_url.is_some() {
        Some(node.enable_relay())
    } else {
        None
    };

    let mut ws: Option<WsClient> = match &relay_url {
        Some(url) => match WsClient::connect(url) {
            Ok(mut client) => {
                let (sign_pub, bind_sig) =
                    nexomesh_core::keys::sign_challenge_b64(&local_key, &format!("bind:{local_key}"));
                let mut reg_id = sign_pub.clone();
                let mut sig = String::new();
                if let Ok(Some(WsFrame::Text(first))) = client.recv_frame() {
                    if extract_json_str(&first, "type").as_deref() == Some("challenge") {
                        if let Some(nonce) = extract_json_str(&first, "nonce") {
                            let (pub_b64, sig_b64) =
                                nexomesh_core::keys::sign_challenge_b64(&local_key, &nonce);
                            reg_id = pub_b64;
                            sig = sig_b64;
                        }
                    }
                }
                let reg = if sig.is_empty() {
                    format!(
                        r#"{{"type":"register","from":"{reg_id}","nodeKey":"{local_key}","bindingSignature":"{bind_sig}"}}"#
                    )
                } else {
                    format!(
                        r#"{{"type":"register","from":"{reg_id}","signature":"{sig}","nodeKey":"{local_key}","bindingSignature":"{bind_sig}"}}"#
                    )
                };
                if let Err(e) = client.send_text(&reg) {
                    eprintln!("[RELAY] error al registrar en {url}: {e}");
                    None
                } else {
                    println!(
                        "[RELAY] conectado a {url} como '{}' (signingPub={})",
                        reg_id,
                        &sign_pub[..sign_pub.len().min(12)]
                    );
                    Some(client)
                }
            }
            Err(e) => {
                eprintln!("[RELAY] no se pudo conectar a {url}: {e}");
                None
            }
        },
        None => None,
    };

    let actual_port = node.local_port().unwrap_or(port);
    println!(
        "[NexoMesh] nodo userspace {local} <-> {peer} (UDP :{actual_port}{})",
        if ws.is_some() { " + fallback DERP WS" } else { " directo" }
    );
    println!("[NexoMesh] cifrado X25519 + ChaCha20-Poly1305 activo. Ctrl+C para salir.");

    let mut last_hello = Instant::now() - Duration::from_secs(10);
    let mut last_heartbeat = Instant::now();
    let mut last_ping = Instant::now() - Duration::from_secs(10);
    let mut seq: u16 = 0;
    let mut ping_sent_at: Option<(u16, Instant)> = None;

    loop {
        node.tick();
        if last_hello.elapsed() >= Duration::from_secs(5) {
            let _ = node.send_hello(&node_id);
            last_hello = Instant::now();
        }

        if let Some(client) = ws.as_mut() {
            if last_heartbeat.elapsed() >= Duration::from_secs(20) {
                let _ = client.send_text(r#"{"type":"heartbeat"}"#);
                last_heartbeat = Instant::now();
            }
        }

        // 1. Enviar pings de prueba si --ping está activo
        if do_ping && last_ping.elapsed() >= Duration::from_secs(2) {
            seq = seq.wrapping_add(1);
            if let Ok(pkt) = build_icmp_echo_request(&local, &peer, seq) {
                if node.send_packet(&pkt).is_ok() {
                    ping_sent_at = Some((seq, Instant::now()));
                    let via = if node.using_direct() { "DIRECT UDP" } else { "RELAY WS" };
                    println!("[PING->{peer}] seq={seq} enviado vía [{via}]");
                }
            }
            last_ping = Instant::now();
        }

        // 2. Vaciar cola saliente hacia el relay WebSocket (frames NM1 binarios)
        if let (Some(rx), Some(client)) = (relay_rx.as_ref(), ws.as_mut()) {
            while let Ok(frame) = rx.try_recv() {
                if let Err(e) = client.send_binary(&frame) {
                    eprintln!("[RELAY] error enviando frame: {e}");
                    break;
                }
            }
        }

        // 3. Procesar datagramas UDP entrantes
        match node.poll_udp_once() {
            Ok(Some(NodeEvent::Hello { vip, name, from })) => {
                println!("[DIRECT UDP] NM_HELLO de {vip} ({name}) en {from} -> NM_ACK enviado");
            }
            Ok(Some(NodeEvent::Ack { vip, from })) => {
                println!("[DIRECT UDP] NM_ACK confirmado con {vip} en {from}");
            }
            Ok(Some(NodeEvent::DiscoPing { vip, tx_id, from })) => {
                println!("[DISCO] Ping #{tx_id} de {vip} en {from}");
            }
            Ok(Some(NodeEvent::DiscoPong { vip, tx_id, from })) => {
                println!("[DISCO] Pong #{tx_id} de {vip} en {from} -> enlace directo activo");
            }
            Ok(Some(NodeEvent::Rekeyed { vip })) => {
                println!("[PFS] Clave de transporte rotada automáticamente con {vip}");
            }
            Ok(Some(NodeEvent::Packet { sender_vip, packet })) => {
                handle_decrypted_packet(&node, &local, &sender_vip, &packet, "DIRECT UDP", &mut ping_sent_at);
            }
            Ok(None) => {}
            Err(e) => eprintln!("[UDP] error: {e}"),
        }

        // 4. Procesar mensajes entrantes desde el relay WebSocket
        let mut ws_closed = false;
        if let Some(client) = ws.as_mut() {
            match client.recv_frame() {
                Ok(Some(WsFrame::Text(txt))) => {
                    if extract_json_str(&txt, "type").as_deref() == Some("relay") {
                        if let Some(b64) = extract_json_str(&txt, "data") {
                            if let Ok(frame) = base64_decode(&b64) {
                                match node.feed_relay_event(&frame) {
                                    Ok(Some(NodeEvent::Packet { sender_vip, packet })) => {
                                        handle_decrypted_packet(
                                            &node,
                                            &local,
                                            &sender_vip,
                                            &packet,
                                            "RELAY WS",
                                            &mut ping_sent_at,
                                        );
                                    }
                                    Ok(Some(NodeEvent::Rekeyed { vip })) => {
                                        println!("[PFS] Clave de transporte rotada vía DERP con {vip}");
                                    }
                                    _ => {}
                                }
                            }
                        }
                    } else if extract_json_str(&txt, "type").as_deref() == Some("peer-joined") {
                        println!("[SIGNALING] nuevo par conectado al relay");
                    } else if extract_json_str(&txt, "type").as_deref() == Some("error") {
                        eprintln!("[SIGNALING] {txt}");
                    }
                }
                Ok(Some(WsFrame::Binary(frame))) => {
                    if let Ok((sender_vip, packet)) = Node::parse_nm1_frame(&frame) {
                        handle_decrypted_packet(
                            &node,
                            &local,
                            &sender_vip,
                            &packet,
                            "RELAY WS",
                            &mut ping_sent_at,
                        );
                    }
                }
                Ok(Some(WsFrame::Closed)) => {
                    eprintln!("[RELAY] conexión cerrada por el servidor");
                    ws_closed = true;
                }
                Ok(None) => {}
                Err(e) => {
                    eprintln!("[RELAY] lectura error: {e}");
                    ws_closed = true;
                }
            }
        }
        if ws_closed {
            ws = None;
        }
    }
}

fn handle_decrypted_packet(
    node: &Node,
    local_vip: &str,
    sender_vip: &str,
    packet: &[u8],
    via: &str,
    ping_sent_at: &mut Option<(u16, Instant)>,
) {
    // ¿Es ICMP Echo Reply para nuestro ping?
    if packet.len() >= 28 && (packet[0] >> 4) == 4 && packet[9] == 1 {
        let ihl = ((packet[0] & 0x0F) as usize) * 4;
        if packet.len() >= ihl + 8 && packet[ihl] == 0 {
            let reply_seq = u16::from_be_bytes([packet[ihl + 6], packet[ihl + 7]]);
            if let Some((expected_seq, sent_at)) = ping_sent_at.as_ref() {
                if *expected_seq == reply_seq {
                    let rtt_ms = sent_at.elapsed().as_secs_f64() * 1000.0;
                    println!("[PONG<-{sender_vip}] seq={reply_seq} rtt={rtt_ms:.2}ms vía [{via}]");
                    *ping_sent_at = None;
                    return;
                }
            }
        }
    }

    // ¿Es ICMP Echo Request hacia nuestra IP virtual? Responder automáticamente.
    if let Some(reply) = try_build_icmp_echo_reply(packet, local_vip) {
        if node.send_packet(&reply).is_ok() {
            println!("[TUN<-{sender_vip}] ICMP Echo Request ({}B) vía [{via}] -> Echo Reply enviado", packet.len());
        }
        return;
    }

    println!("[TUN<-{sender_vip}] paquete IP descifrado ({} bytes) vía [{via}]", packet.len());
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
