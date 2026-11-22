use nexomesh_core::derp::Node;
use nexomesh_core::session;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("nexomesh-cli: keygen | status | tunnel --local <vip> --peer <vip> [--port N] [--relay]");
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
        _ => println!("unknown command"),
    }
}

fn arg(args: &[String], key: &str) -> Option<String> {
    args.iter().position(|a| a == key).and_then(|i| args.get(i + 1)).cloned()
}

fn run_tunnel(args: &[String]) {
    let local = arg(args, "--local").unwrap_or_else(|| "10.0.0.2".to_string());
    let peer = arg(args, "--peer").unwrap_or_else(|| "10.0.0.3".to_string());
    let port: u16 = arg(args, "--port").and_then(|v| v.parse().ok()).unwrap_or(51820);

    // En un despliegue real estas llaves vienen del keypair local y de la invitación.
    let local_key = env::var("NEXOMESH_LOCAL_KEY").unwrap_or_else(|_| format!("local-{local}"));
    let peer_key = env::var("NEXOMESH_PEER_KEY").unwrap_or_else(|_| format!("peer-{peer}"));
    if let Err(e) = session::ensure_session(&local, &local_key, &peer_key) {
        eprintln!("session error: {e}");
        return;
    }

    let mut node = match Node::bind(&local, &peer, port) {
        Ok(n) => n,
        Err(e) => { eprintln!("bind error: {e}"); return; }
    };
    let use_relay = args.iter().any(|a| a == "--relay");
    if use_relay {
        let _rx = node.enable_relay();
        println!("[NexoMesh] userspace node {local} -> {peer} (UDP :{port} + relay WSS listo)");
    } else {
        println!("[NexoMesh] userspace node {local} -> {peer} (UDP :{port} directo)");
    }
    println!("[NexoMesh] sesión Noise/X25519+ChaCha20Poly1305 inicializada");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
