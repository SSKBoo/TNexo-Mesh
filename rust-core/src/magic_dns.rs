//! MagicDNS embebido: resuelve nombres cortos `.mesh` / `.nexomesh` (y nombres
//! simples registrados en la malla) a sus IPs virtuales `10.0.0.x` o `fd7a:...`.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Clone, Debug)]
pub struct DnsRecord {
    pub ipv4: Ipv4Addr,
    pub ipv6: Option<Ipv6Addr>,
}

pub struct MagicDns {
    records: HashMap<String, DnsRecord>,
}

impl MagicDns {
    pub fn new() -> Self {
        Self {
            records: HashMap::new(),
        }
    }

    pub fn register(&mut self, name: &str, ipv4: Ipv4Addr, ipv6: Option<Ipv6Addr>) {
        let norm = normalize_name(name);
        self.records.insert(norm.clone(), DnsRecord { ipv4, ipv6 });
        if !norm.ends_with(".mesh") {
            self.records.insert(format!("{norm}.mesh"), DnsRecord { ipv4, ipv6 });
        }
    }

    pub fn resolve_v4(&self, qname: &str) -> Option<Ipv4Addr> {
        let norm = normalize_name(qname);
        self.records.get(&norm).map(|r| r.ipv4)
    }

    pub fn resolve_v6(&self, qname: &str) -> Option<Ipv6Addr> {
        let norm = normalize_name(qname);
        self.records.get(&norm).and_then(|r| r.ipv6)
    }

    /// Si `query` es una petición DNS UDP (RFC 1035) para un nombre de la malla,
    /// construye la respuesta DNS válida (A=1 o AAAA=28). Devuelve `None` si el
    /// dominio no pertenece a MagicDNS (Split DNS -> delegar al upstream).
    pub fn handle_dns_query(&self, query: &[u8]) -> Option<Vec<u8>> {
        if query.len() < 17 {
            return None;
        }
        let qdcount = u16::from_be_bytes([query[4], query[5]]);
        if qdcount == 0 {
            return None;
        }
        let (qname, next_idx) = parse_qname(query, 12)?;
        if next_idx + 4 > query.len() {
            return None;
        }
        let qtype = u16::from_be_bytes([query[next_idx], query[next_idx + 1]]);
        let qclass = u16::from_be_bytes([query[next_idx + 2], query[next_idx + 3]]);
        if qclass != 1 {
            return None;
        }

        let norm = normalize_name(&qname);
        let rec = self.records.get(&norm)?;

        let mut resp = Vec::with_capacity(query.len() + 32);
        // Transaction ID
        resp.extend_from_slice(&query[0..2]);
        // Flags: QR=1, Opcode=0, AA=1, RD=copy, RA=1, RCODE=0
        let rd = query[2] & 0x01;
        resp.push(0x84 | rd);
        resp.push(0x80);
        // QDCOUNT=1, ANCOUNT=1 (si coincide tipo), NSCOUNT=0, ARCOUNT=0
        resp.extend_from_slice(&1u16.to_be_bytes());
        let answer_rdata: Option<Vec<u8>> = match qtype {
            1 => Some(rec.ipv4.octets().to_vec()),
            28 => rec.ipv6.map(|v6| v6.octets().to_vec()),
            _ => None,
        };
        resp.extend_from_slice(&(if answer_rdata.is_some() { 1u16 } else { 0u16 }).to_be_bytes());
        resp.extend_from_slice(&0u16.to_be_bytes());
        resp.extend_from_slice(&0u16.to_be_bytes());
        // Copiar Question section
        resp.extend_from_slice(&query[12..next_idx + 4]);

        if let Some(rdata) = answer_rdata {
            // Pointer al QNAME en offset 12 (0xC00C)
            resp.extend_from_slice(&0xC00Cu16.to_be_bytes());
            resp.extend_from_slice(&qtype.to_be_bytes());
            resp.extend_from_slice(&1u16.to_be_bytes()); // IN
            resp.extend_from_slice(&60u32.to_be_bytes()); // TTL 60s
            resp.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            resp.extend_from_slice(&rdata);
        }
        Some(resp)
    }
}

fn normalize_name(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn parse_qname(buf: &[u8], mut idx: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    loop {
        if idx >= buf.len() {
            return None;
        }
        let len = buf[idx] as usize;
        idx += 1;
        if len == 0 {
            break;
        }
        if (len & 0xC0) != 0 || idx + len > buf.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&buf[idx..idx + len]).into_owned());
        idx += len;
    }
    Some((labels.join("."), idx))
}
