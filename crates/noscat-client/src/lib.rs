//! noscat-client: the UI-facing layer of the noscat stack.
//!
//! Everything a graphical client needs and a terminal does not: an owned
//! async runtime, identity/relay/tailnet configuration resolved once, and an
//! event stream instead of stderr prints. The primitives are small:
//!
//! - [`Client::connect`] - dial a peer by npub, get the tunnel as a plain
//!   [`TunnelStream`] (`AsyncRead` + `AsyncWrite` of plaintext bytes),
//! - [`Client::listen`] - publish the advert and accept tunnels in the
//!   background; each surfaces as an [`Event::Incoming`] carrying its stream.
//!
//! Everything else is composition on those two: `pipe_stdio` and
//! `serve_stdio` bridge the streams to this process's stdio (that is the
//! whole CLI data plane), `expose` splices incoming streams to a local TCP
//! service, `forward` dials a tunnel per local TCP connection, and
//! `send_file`/`receive_file` delegate to the core's verified transfer
//! protocol. Outcomes arrive as events, so frontends never block on details
//! they do not care about.
//!
//! The CLI (`crates/noscat`) is built on this crate too - it is a terminal
//! skin over the same API a GUI consumes, which keeps the layer honest.
//!
//! ```no_run
//! use noscat_client::{Client, ClientConfig, Event};
//!
//! # fn main() -> Result<(), noscat_client::ClientError> {
//! let mut client = Client::start(ClientConfig::default())?;
//! let events = client.events().take().expect("fresh client");
//! client.pipe_stdio("<peer npub>")?; // blocks until the session closes
//! for ev in events {
//!     if let Event::TunnelClosed { error, .. } = ev {
//!         eprintln!("session ended: {error:?}");
//!     }
//! }
//! # Ok(())
//! # }
//! ```

use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::mpsc as std_mpsc;
use std::sync::Arc;


use noscat_core::relay::DEFAULT_RELAYS;
use noscat_core::tunnel::{self, TunnelInlet, TunnelStream};
use noscat_core::Identity;
use tokio::io::AsyncWriteExt;

/// Where the client's identity comes from.
#[derive(Debug, Clone)]
pub enum IdentitySource {
    /// A fresh ephemeral keypair (the netcat default).
    Ephemeral,
    /// An existing identity, hex secret or `nsec1...`.
    Secret(String),
    /// A file holding the secret (the `serve --identity` convention).
    File(PathBuf),
}

/// Everything a client session needs, resolved once at [`Client::start`].
#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub identity: IdentitySource,
    /// Relay URLs. `None` uses the core's default public set.
    pub relays: Option<Vec<String>>,
    /// The UDP listen address for serve-side tunnels.
    pub listen: Option<SocketAddr>,
    /// A tailnet device directory: tunnels are scoped to the group's epoch
    /// PSK, so only members can connect or be dialed.
    pub tailnet_dir: Option<PathBuf>,
    /// Advert lifetime in seconds.
    pub advert_ttl_secs: u64,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            identity: IdentitySource::Ephemeral,
            relays: None,
            listen: None,
            tailnet_dir: None,
            advert_ttl_secs: 3600,
        }
    }
}

/// What the client does on its own, surfaced for UIs.
pub enum Event {
    /// The serve side is up: the advert is published, tunnels are accepted.
    Listening {
        npub: String,
        addr: SocketAddr,
    },
    /// An inbound tunnel completed its handshake (listener mode).
    Incoming {
        peer: String,
        addr: SocketAddr,
        stream: TunnelStream,
    },
    /// A dialed or accepted tunnel is ready for traffic.
    TunnelUp {
        peer: String,
        addr: SocketAddr,
    },
    /// A tunnel ended; `error` is set when it was not a clean close.
    TunnelClosed {
        peer: String,
        error: Option<String>,
    },
    /// A file transfer finished cleanly (path is the source on send, the
    /// verified final path on receive).
    TransferDone {
        peer: String,
        path: PathBuf,
    },
    /// A file transfer failed.
    TransferFailed {
        peer: String,
        path: Option<PathBuf>,
        error: String,
    },
    /// A background operation (listener, expose, forward) stopped.
    Stopped {
        what: &'static str,
        error: Option<String>,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("identity: {0}")]
    Identity(String),
    #[error("tailnet: {0}")]
    Tailnet(String),
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error(transparent)]
    Tunnel(#[from] tunnel::TunnelError),
}

struct Inner {
    rt: tokio::runtime::Runtime,
    identity: Identity,
    npub: String,
    psk: Option<[u8; 32]>,
    relays: Vec<String>,
    listen: SocketAddr,
    ttl: u64,
    events: std_mpsc::Sender<Event>,
}

impl Inner {
    /// Emit an event; a dropped receiver just means nobody is listening.
    fn emit(&self, ev: Event) {
        let _ = self.events.send(ev);
    }

    /// Dial a peer and finish the session into a byte stream (async half of
    /// [`Client::connect`], reused by the forward loop).
    async fn dial(&self, target: &str) -> Result<(TunnelStream, SocketAddr), tunnel::TunnelError> {
        let session = tunnel::dial_session(&self.identity, target, &self.relays, self.psk.as_ref()).await?;
        let (socket, peer, hs, who) = session.finish().await;
        let stream = TunnelStream::new(socket, peer, hs, TunnelInlet::Exclusive, who);
        Ok((stream, peer))
    }

    /// Bridge a tunnel stream to this process's stdio with netcat
    /// half-close semantics: local EOF sends a FIN, a peer FIN surfaces as
    /// EOF on stdout.
    async fn bridge_stdio(stream: TunnelStream) -> Result<(), tunnel::TunnelError> {
        let (mut rd, mut wr) = tokio::io::split(stream);
        let up = tokio::spawn(async move {
            let mut sin = tokio::io::stdin();
            let n = tokio::io::copy(&mut sin, &mut wr).await?;
            // stdin EOF: send the FIN so the peer sees a clean half-close.
            wr.shutdown().await?;
            io::Result::Ok(n)
        });
        let mut sout = tokio::io::stdout();
        let down = tokio::spawn(async move {
            let n = tokio::io::copy(&mut rd, &mut sout).await?;
            io::Result::Ok(n)
        });
        // Either direction ending is progress; both ending is the session.
        let up = up.await.map_err(|e| io::Error::other(e))??;
        let down = down.await.map_err(|e| io::Error::other(e))??;
        let _ = (up, down);
        Ok(())
    }
}

/// A running noscat client. Cloneable handle; dropping the last handle stops
/// the background runtime and all its tasks. Only the first clone holds the
/// event receiver (see [`Client::events`]).
pub struct Client {
    inner: Arc<Inner>,
    events_rx: Option<std_mpsc::Receiver<Event>>,
}

impl Clone for Client {
    fn clone(&self) -> Self {
        Client {
            inner: self.inner.clone(),
            events_rx: None,
        }
    }
}

impl Client {
    /// Resolve the config, start the runtime, and publish nothing yet: the
    /// client is idle until a command is issued.
    pub fn start(config: ClientConfig) -> Result<Client, ClientError> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        let identity = match &config.identity {
            IdentitySource::Ephemeral => Identity::generate(),
            IdentitySource::Secret(s) => Identity::from_secret(s)
                .map_err(|e| ClientError::Identity(e.to_string()))?,
            IdentitySource::File(path) => {
                let secret = std::fs::read_to_string(path).map_err(|e| {
                    ClientError::Identity(format!("cannot read {}: {e}", path.display()))
                })?;
                Identity::from_secret(secret.trim())
                    .map_err(|e| ClientError::Identity(e.to_string()))?
            }
        };
        let psk = match &config.tailnet_dir {
            Some(dir) => {
                let device = noscat_core::tailnet::Device::open(dir)
                    .map_err(|e| ClientError::Tailnet(e.to_string()))?;
                let psk = device
                    .tunnel_psk()
                    .map_err(|e| ClientError::Tailnet(e.to_string()))?;
                Some(
                    <[u8; 32]>::try_from(psk)
                        .map_err(|_| ClientError::Tailnet("unexpected PSK length".into()))?,
                )
            }
            None => None,
        };
        let (tx, rx) = std_mpsc::channel();
        Ok(Client {
            inner: Arc::new(Inner {
                rt,
                npub: identity.npub(),
                identity,
                psk,
                relays: config.relays.unwrap_or_else(|| {
                    DEFAULT_RELAYS.iter().map(|s| s.to_string()).collect()
                }),
                listen: config.listen.unwrap_or_else(|| "0.0.0.0:41641".parse().unwrap()),
                ttl: config.advert_ttl_secs,
                events: tx,
            }),
            events_rx: Some(rx),
        })
    }

    /// This client's npub (the mesh address UIs display).
    pub fn npub(&self) -> &str {
        &self.inner.npub
    }

    /// Take the event stream (once). Events arrive for every background
    /// operation; blocking operations also return their own errors directly.
    pub fn events(&mut self) -> Option<std_mpsc::Receiver<Event>> {
        self.events_rx.take()
    }

    /// Dial a peer by npub: the tunnel as a byte stream. Blocking for the
    /// advert fetch, punch, and handshake (seconds); call from a worker
    /// thread in UIs.
    pub fn connect(&self, target: &str) -> Result<TunnelStream, ClientError> {
        let inner = self.inner.clone();
        let target = target.to_string();
        let (stream, _peer) = inner.rt.block_on(async {
            let (stream, peer) = inner.dial(&target).await?;
            inner.emit(Event::TunnelUp { peer: target.clone(), addr: peer });
            Ok::<(TunnelStream, SocketAddr), tunnel::TunnelError>((stream, peer))
        })?;
        Ok(stream)
    }

    /// Publish the advert and accept tunnels in the background: each one
    /// arrives as [`Event::Incoming`]. Returns the advertised UDP address.
    /// Concurrent sessions are first-class (one shared socket, a router
    /// demuxing flows per peer).
    pub fn listen(&self) -> Result<SocketAddr, ClientError> {
        let inner = self.inner.clone();
        let listener = inner.rt.block_on(tunnel::bind_listener(
            &inner.identity,
            inner.listen,
            &inner.relays,
            inner.ttl,
            inner.psk.as_ref(),
        ))?;
        let addr = listener.local_addr();
        inner.emit(Event::Listening {
            npub: inner.identity.npub(),
            addr,
        });
        let rt = inner.rt.handle().clone();
        rt.spawn(async move {
            let mut listener = listener;
            loop {
                let session = match listener.accept().await {
                    Ok(s) => s,
                    Err(e) => {
                        inner.emit(Event::Stopped {
                            what: "listener",
                            error: Some(e.to_string()),
                        });
                        return;
                    }
                };
                let (socket, peer, hs, who, data_rx) = session.finish().await;
                let stream =
                    TunnelStream::new(socket, peer, hs, TunnelInlet::Routed(data_rx), who.clone());
                inner.emit(Event::Incoming { peer: who, addr: peer, stream });
            }
        });
        Ok(addr)
    }

    /// Netcat mode, dial side: bridge this process's stdio over a tunnel to
    /// `target`. Blocks until the session closes.
    pub fn pipe_stdio(&self, target: &str) -> Result<(), ClientError> {
        let inner = self.inner.clone();
        let target = target.to_string();
        inner.rt.block_on(async {
            let (stream, peer) = inner.dial(&target).await?;
            inner.emit(Event::TunnelUp { peer: target.clone(), addr: peer });
            let res = Inner::bridge_stdio(stream).await;
            inner.emit(Event::TunnelClosed {
                peer: target,
                error: res.as_ref().err().map(|e| e.to_string()),
            });
            res
        })?;
        Ok(())
    }

    /// Netcat mode, serve side: advertise, take the first peer, bridge stdio.
    /// Blocks until the session closes.
    pub fn serve_stdio(&self) -> Result<(), ClientError> {
        let inner = self.inner.clone();
        inner.rt.block_on(async {
            let session =
                tunnel::serve_session(&inner.identity, inner.listen, &inner.relays, inner.ttl, inner.psk.as_ref()).await?;
            let addr = session.local_addr();
            inner.emit(Event::Listening { npub: inner.identity.npub(), addr });
            let (socket, peer, hs, who) = session.finish().await;
            let stream = TunnelStream::new(socket, peer, hs, TunnelInlet::Exclusive, who.clone());
            inner.emit(Event::TunnelUp { peer: who.clone(), addr: peer });
            let res = Inner::bridge_stdio(stream).await;
            inner.emit(Event::TunnelClosed {
                peer: who,
                error: res.as_ref().err().map(|e| e.to_string()),
            });
            res
        })?;
        Ok(())
    }

    /// Expose a local TCP service to inbound tunnels: every accepted tunnel
    /// is spliced to `to` on its own task, so concurrent peers just work.
    /// Returns immediately with the advertised UDP address; the listener
    /// runs until the client is dropped.
    pub fn expose(&self, to: SocketAddr) -> Result<SocketAddr, ClientError> {
        let inner = self.inner.clone();
        let listener = inner.rt.block_on(tunnel::bind_listener(
            &inner.identity,
            inner.listen,
            &inner.relays,
            inner.ttl,
            inner.psk.as_ref(),
        ))?;
        let addr = listener.local_addr();
        inner.emit(Event::Listening {
            npub: inner.identity.npub(),
            addr,
        });
        let rt = inner.rt.handle().clone();
        rt.spawn(async move {
            let mut listener = listener;
            loop {
                let session = match listener.accept().await {
                    Ok(s) => s,
                    Err(e) => {
                        inner.emit(Event::Stopped {
                            what: "expose",
                            error: Some(e.to_string()),
                        });
                        return;
                    }
                };
                let inner = inner.clone();
                tokio::spawn(async move {
                    let (socket, peer, hs, who, data_rx) = session.finish().await;
                    let stream =
                        TunnelStream::new(socket, peer, hs, TunnelInlet::Routed(data_rx), who.clone());                    inner.emit(Event::TunnelUp { peer: who.clone(), addr: peer });
                    let res = match tokio::net::TcpStream::connect(to).await {
                        Ok(conn) => {
                            let (mut crd, mut cwr) = tokio::io::split(conn);
                            let (mut srd, mut swr) = tokio::io::split(stream);
                            let up = tokio::spawn(async move {
                                tokio::io::copy(&mut crd, &mut swr).await?;
                                swr.shutdown().await
                            });
                            let down = tokio::spawn(async move {
                                tokio::io::copy(&mut srd, &mut cwr).await?;
                                cwr.shutdown().await
                            });
                            tokio::try_join!(flatten(up), flatten(down)).map(|_| ())
                        }
                        Err(e) => Err(io::Error::other(format!("cannot reach tcp/{to}: {e}"))),
                    };
                    inner.emit(Event::TunnelClosed {
                        peer: who,
                        error: res.as_ref().err().map(|e| e.to_string()),
                    });
                });
            }

            async fn flatten<T: Send + 'static>(
                h: tokio::task::JoinHandle<io::Result<T>>,
            ) -> io::Result<T> {
                h.await.map_err(|e| io::Error::other(e))?
            }
        });
        Ok(addr)
    }

    /// Forward a local TCP port over tunnels to `target`: every connection
    /// to `local` dials a fresh tunnel and splices through. Returns
    /// immediately; runs until the client is dropped.
    pub fn forward(&self, target: &str, local: SocketAddr) -> Result<(), ClientError> {
        let inner = self.inner.clone();
        let target = target.to_string();
        let rt = inner.rt.handle().clone();
        rt.spawn(async move {
            let tcp = match tokio::net::TcpListener::bind(local).await {
                Ok(t) => t,
                Err(e) => {
                    inner.emit(Event::Stopped {
                        what: "forward",
                        error: Some(e.to_string()),
                    });
                    return;
                }
            };
            loop {
                let (conn, client) = match tcp.accept().await {
                    Ok(c) => c,
                    Err(e) => {
                        inner.emit(Event::Stopped {
                            what: "forward",
                            error: Some(e.to_string()),
                        });
                        return;
                    }
                };
                let inner = inner.clone();
                let target = target.clone();
                tokio::spawn(async move {
                    let (stream, peer) = match inner.dial(&target).await {
                        Ok(s) => s,
                        Err(e) => {
                            inner.emit(Event::Stopped {
                                what: "forward",
                                error: Some(format!("{client}: {e}")),
                            });
                            return;
                        }
                    };
                    inner.emit(Event::TunnelUp { peer: target.clone(), addr: peer });
                    let (mut crd, mut cwr) = tokio::io::split(conn);
                    let (mut srd, mut swr) = tokio::io::split(stream);
                    let up = tokio::spawn(async move {
                        tokio::io::copy(&mut crd, &mut swr).await?;
                        swr.shutdown().await
                    });
                    let down = tokio::spawn(async move {
                        tokio::io::copy(&mut srd, &mut cwr).await?;
                        cwr.shutdown().await
                    });
                    let res = tokio::try_join!(flatten(up), flatten(down));
                    inner.emit(Event::TunnelClosed {
                        peer: target,
                        error: res.as_ref().err().map(|e| e.to_string()),
                    });
                });
            }

            async fn flatten<T: Send + 'static>(
                h: tokio::task::JoinHandle<io::Result<T>>,
            ) -> io::Result<T> {
                h.await.map_err(|e| io::Error::other(e))?
            }
        });
        Ok(())
    }

    /// Send a file to a peer (resume-aware, sha256-verified at the peer).
    /// Returns immediately; [`Event::TransferDone`]/[`TransferFailed`] report
    /// the outcome.
    pub fn send_file(&self, path: PathBuf, target: &str) {
        let inner = self.inner.clone();
        let target = target.to_string();
        let source = path.clone();
        let rt = inner.rt.handle().clone();
        rt.spawn(async move {
            match tunnel::send_file(
                &inner.identity,
                &target,
                &source,
                &inner.relays,
                inner.psk.as_ref(),
            )
            .await
            {
                Ok(()) => inner.emit(Event::TransferDone { peer: target, path: source }),
                Err(e) => inner.emit(Event::TransferFailed {
                    peer: target,
                    path: Some(source),
                    error: e.to_string(),
                }),
            }
        });
    }

    /// Receive one file into `out_dir`. Returns immediately; the outcome
    /// arrives as [`Event::TransferDone`] (path = the verified final file) or
    /// [`Event::TransferFailed`].
    pub fn receive_file(&self, out_dir: PathBuf) {
        let inner = self.inner.clone();
        let rt = inner.rt.handle().clone();
        rt.spawn(async move {
            match tunnel::receive_file(
                &inner.identity,
                inner.listen,
                &inner.relays,
                inner.ttl,
                &out_dir,
                inner.psk.as_ref(),
            )
            .await
            {
                Ok((who, path)) => inner.emit(Event::TransferDone { peer: who, path }),
                Err(e) => inner.emit(Event::TransferFailed {
                    peer: String::new(),
                    path: None,
                    error: e.to_string(),
                }),
            }
        });
    }
}
