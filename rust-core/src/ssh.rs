//! NexoMesh SSH sin llaves (estilo Tailscale SSH):
//! autentica sesiones SSH mediante identidad verificada del NetMap, grupo OIDC (`group:dev`)
//! y política ACL (`allow_ssh`), emitiendo tickets efímeros firmados con Ed25519 sin usar `~/.ssh/authorized_keys`.

use crate::acl::{Action, IdentityAclEngine, NodeIdentity};
use crate::keys::{derive_ed25519_keypair, sign_challenge_b64};
use crate::ws_client::{base64_decode, base64_encode};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug)]
pub struct MeshSshTicket {
    pub user_id: String,
    pub src_vip: String,
    pub dst_vip: String,
    pub expires_at_sec: u64,
    pub issuer_pub_b64: String,
    pub signature_b64: String,
}

impl MeshSshTicket {
    pub fn canonical_message(&self) -> String {
        format!(
            "nexomesh-ssh-v1|{}|{}|{}|{}",
            self.user_id, self.src_vip, self.dst_vip, self.expires_at_sec
        )
    }
}

pub fn issue_mesh_ssh_ticket(
    authority_seed: &str,
    acl: &IdentityAclEngine,
    src: &NodeIdentity,
    dst: &NodeIdentity,
    ttl_secs: u64,
) -> Result<MeshSshTicket, String> {
    if acl.evaluate_ssh(src, dst) != Action::Allow {
        return Err(format!(
            "ACL SSH denegada: '{}' no tiene permiso SSH sobre '{}' ({})",
            src.user_id, dst.ip, dst.tags.join(",")
        ));
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let expires_at_sec = now.saturating_add(ttl_secs.max(10));
    let mut ticket = MeshSshTicket {
        user_id: src.user_id.clone(),
        src_vip: src.ip.to_string(),
        dst_vip: dst.ip.to_string(),
        expires_at_sec,
        issuer_pub_b64: String::new(),
        signature_b64: String::new(),
    };
    let (pub_b64, sig_b64) = sign_challenge_b64(authority_seed, &ticket.canonical_message());
    ticket.issuer_pub_b64 = pub_b64;
    ticket.signature_b64 = sig_b64;
    Ok(ticket)
}

pub fn verify_mesh_ssh_ticket(
    ticket: &MeshSshTicket,
    expected_authority_seed: Option<&str>,
    now_sec: Option<u64>,
) -> bool {
    let now = now_sec.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    });
    if ticket.expires_at_sec < now {
        return false;
    }
    if let Some(seed) = expected_authority_seed {
        let (_, expected_pub) = derive_ed25519_keypair(seed);
        if base64_encode(&expected_pub) != ticket.issuer_pub_b64 {
            return false;
        }
    }
    let Ok(pub_raw) = base64_decode(&ticket.issuer_pub_b64) else {
        return false;
    };
    let Ok(sig_raw) = base64_decode(&ticket.signature_b64) else {
        return false;
    };
    if pub_raw.len() != 32 || sig_raw.len() != 64 {
        return false;
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pub_raw);
    let Ok(vk) = VerifyingKey::from_bytes(&pk_arr) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(&sig_raw) else {
        return false;
    };
    vk.verify(ticket.canonical_message().as_bytes(), &sig).is_ok()
}
