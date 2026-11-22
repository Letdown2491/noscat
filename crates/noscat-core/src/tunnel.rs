//! The data plane: a Noise-XK session over one UDP socket pair.
//!
//! MVP topology ("netcat mode"): `serve` binds a UDP port, advertises it over
//! Nostr relays, and pipes the first peer that completes the handshake to its
//! stdio. `pipe` fetches the target's advert from the relays, handshakes, and
//! pipes its stdio into the tunnel. One datagram = one Noise message.

use std::net::SocketAddr;
use std::time::Duration;

use nostr::prelude::*;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::time::{sleep, timeout};

use crate::advert::{Advert, Endpoint, Transport};
use crate::identity::Identity;
use crate::noise::{self, NoiseError};

/// How long `pipe` waits for the target's advert to show up on the relays.
const ADVERT_WAIT: Duration = Duration::from_secs(30);
/// How long the handshake may take before both sides give up.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
/// UDP read buffer: Noise caps messages well below the 65535 IP limit.
const BUF: usize = 65535;

#[derive(Debug, thiserror::Error)]
pub enum TunnelError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Noise(#[from] NoiseError),
    #[error(transparent)]
    Snow(#[from] snow::Error),
    #[error(transparent)]
    Relay(#[from] crate::relay::RelayError),
    #[error("no advert for {0} found on the relays within {1:?}")]
    AdvertTimeout(String, Duration),
    #[error("handshake timed out")]
    HandshakeTimeout,
    #[error("peer did not complete the handshake")]
    NoHandshake,
    #[error("advert does not carry a usable noise key or endpoint")]
    BadAdvert,
    #[error("first packet from {0} is not a handshake opener")]
    NotAHandshake(SocketAddr),
}

/// The identity's Noise keypair (public, private), derived from its secret —
/// see [`crate::noise`] for why this is a derivation, not the raw key.
pub fn noise_keypair(identity: &Identity) -> Result<([u8; 32], [u8; 32]), TunnelError> {
    let secret: [u8; 32] = identity
        .keys()
        .secret_key()
        .as_secret_bytes()
        .try_into()
        .map_err(|_| NoiseError::KeyLen)?;
    let privkey = noise::noise_static_from_identity(&secret)?;
    Ok((noise::noise_public(&privkey), privkey))
}

/// Bridge stdio over the encrypted session until both sides close.
///
/// Local stdin EOF sends a FIN (an authenticated empty Noise payload); a FIN
/// from the peer ends the receive side; the session ends when both happened.
async fn pump<R, W>(
    mut reader: R,
    mut writer: W,
    socket: UdpSocket,
    peer: SocketAddr,
    mut session: snow::TransportState,
) -> Result<(), TunnelError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut plain = [0u8; BUF];
    let mut wire = [0u8; BUF];

    let mut stdin_open = true;
    loop {
        tokio::select! {
            n = reader.read(&mut plain), if stdin_open => {
                match n {
                    Ok(0) => {
                        let n = session.write_message(b"", &mut wire)?;
                        socket.send_to(&wire[..n], peer).await?;
                        stdin_open = false;
                    }
                    Ok(n) => {
                        let n = session.write_message(&plain[..n], &mut wire)?;
                        socket.send_to(&wire[..n], peer).await?;
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            r = socket.recv_from(&mut wire) => {
                let (n, from) = r?;
                if from != peer {
                    tracing::debug!(%from, "ignoring packet from stranger");
                    continue;
                }
                match session.read_message(&wire[..n], &mut plain) {
                    Ok(0) if !stdin_open => return Ok(()), // mutual close
                    Ok(0) => {}                            // peer FIN; keep draining
                    Ok(m) => {
                        writer.write_all(&plain[..m]).await?;
                        writer.flush().await?;
                    }
                    Err(snow::Error::Decrypt) => {
                        tracing::warn!("dropping undecryptable datagram");
                    }
                    Err(e) => return Err(e.into()),
                }
            }
        }
    }
}

/// Serve one tunnel: bind `listen`, advertise, handshake with the first peer,
/// then bridge stdio over the encrypted channel. Resolves when the session
/// closes, reporting the peer's identity (npub when discoverable).
pub async fn serve(
    identity: &Identity,
    listen: SocketAddr,
    relays: &[String],
    ttl_secs: u64,
) -> Result<String, TunnelError> {
    let (noise_pub, noise_priv) = noise_keypair(identity)?;

    let socket = UdpSocket::bind(listen).await?;
    let local = socket.local_addr()?;
    let mut hs = noise::responder(&noise_priv)?;

    // When bound to an unspecified address, discover the interface IP the OS
    // would actually use to reach the internet (routing probe sends no
    // packets), so the advert carries a dialable address.
    let advertised_ip = if local.ip().is_unspecified() {
        match UdpSocket::bind(if local.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).await {
            Ok(probe) => match probe.connect("8.8.8.8:80").await {
                Ok(()) => probe.local_addr()?.ip(),
                Err(e) => {
                    tracing::warn!("cannot probe local IP: {e}; advertising bind address");
                    local.ip()
                }
            },
            Err(e) => {
                tracing::warn!("cannot probe local IP: {e}; advertising bind address");
                local.ip()
            }
        }
    } else {
        local.ip()
    };

    // Advertise the real bound address + Noise key, signed by our npub.
    let endpoint = Endpoint {
        transport: Transport::Udp,
        addr: SocketAddr::new(advertised_ip, local.port()).to_string(),
    };
    crate::relay::publish_advert(identity, vec![endpoint], noise_pub, ttl_secs, relays).await?;
    eprintln!(
        "# 🐈 serving on udp/{local} as {} — waiting for a peer… (Ctrl-C to quit)",
        identity.npub()
    );

    // First datagram must be XK message 1 (-> e).
    let mut wire = [0u8; BUF];
    let mut plain = [0u8; BUF];
    let (n, peer) = loop {
        let (n, from) = socket.recv_from(&mut wire).await?;
        match hs.read_message(&wire[..n], &mut plain) {
            Ok(_) => break (n, from),
            Err(e) => tracing::debug!(%from, %e, "not a handshake opener; ignoring"),
        }
    };
    let _ = n;

    // <- e, ee, s, er
    let n = hs.write_message(b"", &mut wire)?;
    socket.send_to(&wire[..n], peer).await?;

    // -> s, se
    match timeout(HANDSHAKE_TIMEOUT, socket.recv_from(&mut wire)).await {
        Ok(Ok((n, from))) if from == peer => {
            hs.read_message(&wire[..n], &mut plain)?;
        }
        Ok(Ok((_, from))) => return Err(TunnelError::NotAHandshake(from)),
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => return Err(TunnelError::HandshakeTimeout),
    }
    let initiator_noise: [u8; 32] = hs
        .get_remote_static()
        .ok_or(TunnelError::NoHandshake)?
        .try_into()
        .map_err(|_| TunnelError::NoHandshake)?;
    let session = noise::into_transport(hs)?;

    // The initiator's Noise key binds to its npub through its signed advert.
    let who = match crate::relay::fetch_advert_for(relays, Some(initiator_noise), None).await? {
        Some(advert) => advert.npub.to_string(),
        None => format!("noise key {}", hex::encode(initiator_noise)),
    };
    eprintln!("# 🔗 tunnel up with {who} — bridging stdio");

    pump(tokio::io::stdin(), tokio::io::stdout(), socket, peer, session).await?;
    Ok(who)
}

/// Dial a peer by npub: fetch its advert from the relays, handshake, bridge stdio.
pub async fn pipe(identity: &Identity, target: &str, relays: &[String]) -> Result<(), TunnelError> {
    let target_pubkey =
        PublicKey::parse(target).map_err(|_| TunnelError::BadAdvert)?;

    let deadline = tokio::time::Instant::now() + ADVERT_WAIT;
    let advert: Advert = loop {
        if let Some(a) =
            crate::relay::fetch_advert_for(relays, None, Some(target_pubkey)).await?
        {
            break a;
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(TunnelError::AdvertTimeout(target.to_string(), ADVERT_WAIT));
        }
        sleep(Duration::from_secs(2)).await;
    };
    let addr: SocketAddr = advert
        .endpoints
        .first()
        .map(|e| e.addr.clone())
        .and_then(|a| a.parse().ok())
        .ok_or(TunnelError::BadAdvert)?;
    let server_noise: [u8; 32] = advert.noise_pub;

    let bind: SocketAddr = if addr.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let socket = UdpSocket::bind(bind).await?;

    let (_noise_pub, noise_priv) = noise_keypair(identity)?;
    let mut hs = noise::initiator(&noise_priv, &server_noise)?;
    let mut wire = [0u8; BUF];

    // -> e
    let n = hs.write_message(b"", &mut wire)?;
    socket.send_to(&wire[..n], addr).await?;
    // <- e, ee, s, er
    let n = timeout(HANDSHAKE_TIMEOUT, socket.recv(&mut wire))
        .await
        .map_err(|_| TunnelError::HandshakeTimeout)??;
    let mut plain = [0u8; BUF];
    hs.read_message(&wire[..n], &mut plain)?;
    // -> s, se
    let n = hs.write_message(b"", &mut wire)?;
    socket.send_to(&wire[..n], addr).await?;
    let session = noise::into_transport(hs)?;

    eprintln!("# 🔗 tunnel up with {target} at udp/{addr} — bridging stdio");
    pump(tokio::io::stdin(), tokio::io::stdout(), socket, addr, session).await
}
