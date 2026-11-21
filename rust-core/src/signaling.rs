use std::collections::HashMap;

pub struct SignalingClient {
    pub endpoint: String,
    peers: HashMap<String, String>,
}

impl SignalingClient {
    pub fn new(endpoint: &str) -> Self {
        Self { endpoint: endpoint.to_string(), peers: HashMap::new() }
    }
    pub fn register(&mut self, public_key: &str) {
        self.peers.insert(public_key.to_string(), public_key.to_string());
    }
}
