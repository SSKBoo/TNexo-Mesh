use crate::peer::Peer;
use std::collections::HashMap;

pub struct Mesh {
    peers: HashMap<String, Peer>,
    backoff_ms: u64,
}

impl Mesh {
    pub fn new() -> Self {
        Self { peers: HashMap::new(), backoff_ms: 1000 }
    }
    pub fn add_peer(&mut self, peer: Peer) {
        self.peers.insert(peer.id.clone(), peer);
    }
    pub fn remove_peer(&mut self, id: &str) {
        self.peers.remove(id);
    }
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }
    pub fn next_backoff(&mut self) -> u64 {
        let v = self.backoff_ms;
        self.backoff_ms = (self.backoff_ms * 2).min(60000);
        v
    }
}
