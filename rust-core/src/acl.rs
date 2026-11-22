//! Motor de políticas / ACLs por nodo (inspirado en Tailscale NetMap ACLs).

use crate::routing::cidr_matches;
use std::net::Ipv4Addr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Allow,
    Deny,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proto {
    Any,
    Tcp,
    Udp,
    Icmp,
}

impl Proto {
    pub fn from_ip_proto(p: u8) -> Self {
        match p {
            1 => Proto::Icmp,
            6 => Proto::Tcp,
            17 => Proto::Udp,
            _ => Proto::Any,
        }
    }
}

#[derive(Clone, Debug)]
pub struct AclRule {
    pub action: Action,
    pub src_cidr: String,
    pub dst_cidr: String,
    pub proto: Proto,
    pub dst_port: Option<u16>,
}

pub struct AclEngine {
    rules: Vec<AclRule>,
    default_action: Action,
}

impl AclEngine {
    pub fn new(default_action: Action) -> Self {
        Self {
            rules: Vec::new(),
            default_action,
        }
    }

    pub fn add_rule(&mut self, rule: AclRule) {
        self.rules.push(rule);
    }

    pub fn evaluate(&self, src: Ipv4Addr, dst: Ipv4Addr, proto: u8, dst_port: u16) -> Action {
        let pkt_proto = Proto::from_ip_proto(proto);
        for rule in &self.rules {
            if !cidr_matches(&rule.src_cidr, src) || !cidr_matches(&rule.dst_cidr, dst) {
                continue;
            }
            if rule.proto != Proto::Any && rule.proto != pkt_proto {
                continue;
            }
            if let Some(p) = rule.dst_port {
                if p != dst_port {
                    continue;
                }
            }
            return rule.action;
        }
        self.default_action
    }
}
