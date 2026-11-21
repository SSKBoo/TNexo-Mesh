//! Cliente STUN mínimo (RFC 5389): Binding Request y parseo de XOR-MAPPED-ADDRESS.

pub const STUN_MAGIC: u32 = 0x2112_A442;

pub fn stun_binding_request() -> Vec<u8> {
    let mut buf = vec![0u8; 20];
    buf[0] = 0x00;
    buf[1] = 0x01; // Binding Request
    buf[2..4].copy_from_slice(&0u16.to_be_bytes()); // sin atributos
    buf[4..8].copy_from_slice(&STUN_MAGIC.to_be_bytes());
    // transaction ID (12 bytes) determinista para tests
    for (i, b) in buf[8..20].iter_mut().enumerate() {
        *b = i as u8;
    }
    buf
}

/// Parsea un mensaje STUN y devuelve el endpoint mapeado como "ip:puerto".
pub fn parse_mapped_address(buf: &[u8]) -> Option<String> {
    if buf.len() < 20 {
        return None;
    }
    let msg_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let end = (20 + msg_len).min(buf.len());
    let mut idx = 20;
    while idx + 4 <= end {
        let attr_type = u16::from_be_bytes([buf[idx], buf[idx + 1]]);
        let attr_len = u16::from_be_bytes([buf[idx + 2], buf[idx + 3]]) as usize;
        let val = idx + 4;
        if val + attr_len > end {
            break;
        }
        // 0x0020 XOR-MAPPED-ADDRESS, 0x0001 MAPPED-ADDRESS
        if (attr_type == 0x0020 || attr_type == 0x0001) && attr_len >= 8 && buf[val + 1] == 0x01 {
            let raw_port = u16::from_be_bytes([buf[val + 2], buf[val + 3]]);
            let (port, ip) = if attr_type == 0x0020 {
                (
                    raw_port ^ 0x2112,
                    format!(
                        "{}.{}.{}.{}",
                        buf[val + 4] ^ 0x21,
                        buf[val + 5] ^ 0x12,
                        buf[val + 6] ^ 0xA4,
                        buf[val + 7] ^ 0x42,
                    ),
                )
            } else {
                (
                    raw_port,
                    format!(
                        "{}.{}.{}.{}",
                        buf[val + 4], buf[val + 5], buf[val + 6], buf[val + 7]
                    ),
                )
            };
            return Some(format!("{}:{}", ip, port));
        }
        let padded = (attr_len + 3) & !3;
        idx = val + padded;
    }
    None
}
