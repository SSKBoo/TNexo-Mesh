#[derive(Clone, Debug)]
pub struct Peer {
    pub id: String,
    pub public_key: String,
    pub online: bool,
}

impl Peer {
    pub fn new(id: &str, public_key: &str) -> Self {
        Self { id: id.to_string(), public_key: public_key.to_string(), online: false }
    }
}
