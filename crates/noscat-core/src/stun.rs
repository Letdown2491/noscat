//! Minimal STUN client (RFC 5389 Binding request only) for server-reflexive
//! discovery — just enough to learn "what does the internet see as my
//! address on this socket", which is what NAT hole punching needs.
//!
//! Runs on the tunnel's own UDP socket so the discovered mapping is the one a
//! peer can punch at.

use std::net::SocketAddr;
use std::time::Duration;

use rand::RngCore;
use tokio::net::UdpSocket;
use tokio::time::timeout;

/// Public STUN servers tried in order; the first answer wins. These are
/// infrastructure-grade free endpoints (Google's, Cloudflare's).
pub const DEFAULT_STUN_SERVERS: &[&str] =
    &["stun.l.google.com:19302", "stun.cloudflare.com:3478"];

const MAGIC_COOKIE: u32 = 0x2112_a44d;
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_RESPONSE: u16 = 0x0101;
const ATTR_XOR_MAPPED: u16 = 0x0020;
const ATTR_MAPPED: u16 = 0x0001;

#[derive(Debug, thiserror::Error)]
pub enum StunError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("cannot resolve STUN server {0}")]
    Resolve(String),
    #[error("no answer from any STUN server")]
    NoAnswer,
    #[error("malformed STUN response")]
    Malformed,
}

/// Send a Binding request from `socket` to a STUN server and parse the
/// XOR-MAPPED-ADDRESS (falling back to MAPPED-ADDRESS).
pub async fn external_addr(socket: &UdpSocket, stun_server: &str) -> Result<SocketAddr, StunError> {
    let want_v4 = socket.local_addr()?.is_ipv4();
    let server: SocketAddr = tokio::net::lookup_host((stun_server, 0))
        .await
        .map_err(|_| StunError::Resolve(stun_server.to_string()))?
        .find(|a| a.is_ipv4() == want_v4)
        .ok_or_else(|| StunError::Resolve(stun_server.to_string()))?;

    // Binding request: header only (type, len=0, cookie, txid).
    let mut txid = [0u8; 12];
    rand::rng().fill_bytes(&mut txid);
    let mut req = [0u8; 20];
    req[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    req[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    req[8..20].copy_from_slice(&txid);
    socket.send_to(&req, server).await?;

    let mut buf = [0u8; 1500];
    let deadline = Duration::from_secs(3);
    loop {
        let (n, from) = timeout(deadline, socket.recv_from(&mut buf))
            .await
            .map_err(|_| StunError::NoAnswer)??;
        if from != server {
            continue; // not our STUN server; keep waiting
        }
        if let Some(addr) = parse_response(&buf[..n], &txid)? {
            return Ok(addr);
        }
        // A non-matching response (e.g. an error); keep waiting for success.
    }
}

/// Try each default STUN server until one answers.
pub async fn discover(socket: &UdpSocket) -> Result<SocketAddr, StunError> {
    let mut last = StunError::NoAnswer;
    for server in DEFAULT_STUN_SERVERS {
        match external_addr(socket, server).await {
            Ok(addr) => return Ok(addr),
            Err(e) => last = e,
        }
    }
    Err(last)
}

fn parse_response(msg: &[u8], txid: &[u8; 12]) -> Result<Option<SocketAddr>, StunError> {
    if msg.len() < 20 {
        return Err(StunError::Malformed);
    }
    let mtype = u16::from_be_bytes([msg[0], msg[1]]);
    let mlen = u16::from_be_bytes([msg[2], msg[3]]) as usize;
    let cookie = u32::from_be_bytes([msg[4], msg[5], msg[6], msg[7]]);
    if cookie != MAGIC_COOKIE || &msg[8..20] != txid {
        return Err(StunError::Malformed);
    }
    if mtype != BINDING_RESPONSE {
        return Ok(None);
    }
    let end = (20 + mlen).min(msg.len());
    let mut attrs = &msg[20..end];
    // Walk TLVs: [type:2][len:2][value padded to 4].
    while attrs.len() >= 4 {
        let atype = u16::from_be_bytes([attrs[0], attrs[1]]);
        let alen = u16::from_be_bytes([attrs[2], attrs[3]]) as usize;
        if attrs.len() < 4 + alen {
            break;
        }
        let value = &attrs[4..4 + alen];
        if atype == ATTR_XOR_MAPPED || atype == ATTR_MAPPED {
            if let Some(addr) = parse_address(value, atype == ATTR_XOR_MAPPED, txid) {
                return Ok(Some(addr));
            }
        }
        attrs = &attrs[4 + alen.div_ceil(4) * 4..];
    }
    Ok(None)
}

fn parse_address(v: &[u8], xor: bool, txid: &[u8; 12]) -> Option<SocketAddr> {
    if v.len() < 8 || v[1] != 0x01 {
        return None; // only IPv4 for now
    }
    let mut port = u16::from_be_bytes([v[2], v[3]]);
    let mut octets = [v[4], v[5], v[6], v[7]];
    if xor {
        port ^= (MAGIC_COOKIE >> 16) as u16;
        for (i, o) in octets.iter_mut().enumerate() {
            *o ^= (MAGIC_COOKIE >> (24 - 8 * i)) as u8;
        }
        // IPv6 would XOR the address against cookie+txid; IPv4 only needs the cookie.
        let _ = txid;
    }
    Some(SocketAddr::from((std::net::Ipv4Addr::from(octets), port)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Canned XOR-MAPPED-ADDRESS attribute baked from known inputs:
    /// addr 203.0.113.7:54321, cookie 0x2112a44d.
    #[test]
    fn parses_xor_mapped_address() {
        let port: u16 = 54321;
        let ip = [203, 0, 113, 7];
        let xport = port ^ (MAGIC_COOKIE >> 16) as u16;
        let xaddr: Vec<u8> = ip
            .iter()
            .zip(0..)
            .map(|(o, i)| o ^ (MAGIC_COOKIE >> (24 - 8 * i)) as u8)
            .collect();

        // Build a full success response with one XOR-MAPPED-ADDRESS attribute.
        // Message length covers the whole TLV: type + len + value = 12.
        let mut msg = Vec::new();
        msg.extend_from_slice(&BINDING_RESPONSE.to_be_bytes());
        msg.extend_from_slice(&12u16.to_be_bytes());
        msg.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        let txid = [9u8; 12];
        msg.extend_from_slice(&txid);
        msg.extend_from_slice(&ATTR_XOR_MAPPED.to_be_bytes());
        msg.extend_from_slice(&8u16.to_be_bytes());
        msg.push(0);
        msg.push(0x01);
        msg.extend_from_slice(&xport.to_be_bytes());
        msg.extend_from_slice(&xaddr);

        let addr = parse_response(&msg, &txid).expect("parse").expect("addr");
        assert_eq!(addr.to_string(), "203.0.113.7:54321");
    }

    #[test]
    fn rejects_wrong_transaction_id() {
        let mut msg = vec![0u8; 20];
        msg[0..2].copy_from_slice(&BINDING_RESPONSE.to_be_bytes());
        msg[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
        assert!(parse_response(&msg, &[1u8; 12]).is_err());
    }
}
