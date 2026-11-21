pub struct TurnCredentials {
    pub username: String,
    pub password: String,
    pub ttl: u32,
}

pub fn allocate() -> TurnCredentials {
    TurnCredentials {
        username: "user".to_string(),
        password: "pass".to_string(),
        ttl: 3600,
    }
}
