#[derive(Clone, Debug)]
pub struct Route {
    pub prefix: String,
    pub peer_id: String,
    pub relay: bool,
}

pub struct RoutingTable {
    routes: Vec<Route>,
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

    pub fn longest_prefix_match(&self, ip: &str) -> Option<Route> {
        let mut best: Option<&Route> = None;
        let mut best_len = 0;
        for r in &self.routes {
            if ip.starts_with(&r.prefix) || prefix_matches(&r.prefix, ip) {
                if r.prefix.len() > best_len {
                    best = Some(r);
                    best_len = r.prefix.len();
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
    // simple: prefix like "10.0.0." matches ip starting with it
    ip.starts_with(prefix.trim_end_matches('/'))
}

pub fn route(dest_ip: &str, table: &RoutingTable) -> Option<String> {
    table.route(dest_ip)
}
