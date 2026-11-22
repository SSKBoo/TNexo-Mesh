//! Enrutamiento L3 CIDR (Subnet Routers, Exit Nodes 0.0.0.0/0 y malla 10.0.0.0/24).

use std::net::Ipv4Addr;

#[derive(Clone, Debug)]
pub struct Route {
    pub prefix: String,
    pub peer_id: String,
    pub relay: bool,
}

pub struct RoutingTable {
    routes: Vec<Route>,
}

/// Parsea `"192.168.1.0/24"` o `"10.0.0."` a `(network_u32, mask_u32, prefix_len)`.
pub fn parse_cidr(cidr: &str) -> Option<(u32, u32, u8)> {
    let clean = cidr.trim();
    if let Some((ip_str, len_str)) = clean.split_once('/') {
        let ip: Ipv4Addr = ip_str.parse().ok()?;
        let bits: u8 = len_str.parse().ok()?;
        if bits > 32 {
            return None;
        }
        let mask = if bits == 0 { 0 } else { !0u32 << (32 - bits) };
        return Some((u32::from(ip) & mask, mask, bits));
    }
    if let Ok(ip) = clean.parse::<Ipv4Addr>() {
        return Some((u32::from(ip), !0u32, 32));
    }
    None
}

pub fn cidr_matches(cidr: &str, ip: Ipv4Addr) -> bool {
    if let Some((net, mask, _)) = parse_cidr(cidr) {
        return (u32::from(ip) & mask) == net;
    }
    let s = ip.to_string();
    s.starts_with(cidr.trim_end_matches('/'))
}

impl RoutingTable {
    pub fn new() -> Self {
        Self { routes: Vec::new() }
    }

    pub fn add(&mut self, prefix: &str, peer_id: &str, relay: bool) {
        self.routes.push(Route {
            prefix: prefix.to_string(),
            peer_id: peer_id.to_string(),
            relay,
        });
    }

    /// Añade una ruta CIDR de subred (Subnet Router o Exit Node `0.0.0.0/0`).
    pub fn advertise_subnet(&mut self, cidr: &str, peer_id: &str, relay: bool) {
        self.add(cidr, peer_id, relay);
    }

    pub fn longest_prefix_match(&self, ip: &str) -> Option<Route> {
        let parsed_ip: Option<Ipv4Addr> = ip.trim().parse().ok();
        let mut best: Option<&Route> = None;
        let mut best_score: i32 = -1;
        for r in &self.routes {
            if let (Some(v4), Some((net, mask, bits))) = (parsed_ip, parse_cidr(&r.prefix)) {
                if (u32::from(v4) & mask) == net {
                    let score = bits as i32;
                    if score > best_score {
                        best = Some(r);
                        best_score = score;
                    }
                }
            } else if ip.starts_with(&r.prefix) || prefix_matches(&r.prefix, ip) {
                let score = r.prefix.len() as i32;
                if score > best_score {
                    best = Some(r);
                    best_score = score;
                }
            }
        }
        best.cloned()
    }

    pub fn route(&self, dest_ip: &str) -> Option<String> {
        self.longest_prefix_match(dest_ip).map(|r| r.peer_id)
    }
}

fn prefix_matches(prefix: &str, ip: &str) -> bool {
    ip.starts_with(prefix.trim_end_matches('/'))
}

pub fn route(dest_ip: &str, table: &RoutingTable) -> Option<String> {
    table.route(dest_ip)
}
