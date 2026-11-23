//! Motor de políticas / ACLs por nodo y por identidad/etiquetas (OIDC, `group:dev`, `tag:server`).

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

/// Identidad humana/servicio de un nodo en el NetMap (OIDC/SSO + etiquetas).
#[derive(Clone, Debug)]
pub struct NodeIdentity {
    pub ip: Ipv4Addr,
    pub user_id: String,
    pub groups: Vec<String>,
    pub tags: Vec<String>,
}

impl NodeIdentity {
    pub fn matches_selector(&self, selector: &str) -> bool {
        let sel = selector.trim();
        if sel == "*" || sel == "autogroup:member" {
            return true;
        }
        if sel.starts_with("group:") {
            return self.groups.iter().any(|g| g == sel);
        }
        if sel.starts_with("tag:") {
            return self.tags.iter().any(|t| t == sel);
        }
        if sel == self.user_id {
            return true;
        }
        cidr_matches(sel, self.ip)
    }
}

/// Regla ACL basada en identidad OIDC, grupos (`group:dev`), tags (`tag:server`) y SSH sin llaves.
#[derive(Clone, Debug)]
pub struct IdentityAclRule {
    pub action: Action,
    pub src_selector: String,
    pub dst_selector: String,
    pub proto: Proto,
    pub dst_port: Option<u16>,
    pub allow_ssh: bool,
}

pub struct IdentityAclEngine {
    rules: Vec<IdentityAclRule>,
    default_action: Action,
}

impl IdentityAclEngine {
    pub fn new(default_action: Action) -> Self {
        Self {
            rules: Vec::new(),
            default_action,
        }
    }

    pub fn add_rule(&mut self, rule: IdentityAclRule) {
        self.rules.push(rule);
    }

    pub fn evaluate_flow(
        &self,
        src: &NodeIdentity,
        dst: &NodeIdentity,
        proto: u8,
        dst_port: u16,
    ) -> Action {
        let pkt_proto = Proto::from_ip_proto(proto);
        for rule in &self.rules {
            if !src.matches_selector(&rule.src_selector) || !dst.matches_selector(&rule.dst_selector) {
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

    /// Evalúa si el usuario/nodo origen puede abrir NexoMesh SSH sin llaves hacia el nodo destino.
    pub fn evaluate_ssh(&self, src: &NodeIdentity, dst: &NodeIdentity) -> Action {
        for rule in &self.rules {
            if !src.matches_selector(&rule.src_selector) || !dst.matches_selector(&rule.dst_selector) {
                continue;
            }
            if rule.allow_ssh {
                return rule.action;
            }
        }
        Action::Deny
    }
}
