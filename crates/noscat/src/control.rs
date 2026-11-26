//! One process per device: the one running it serves this loopback
//! control channel, and every other `noscat` command on the same state
//! directory runs through it.
//!
//! `<dir>/control.json` (owner-only) holds the port and a random token.
//! A request is one JSON line `{"token", "op"}`; replies are JSON lines
//! ending with `done` or `error`. `pipe` switches the connection to raw
//! bytes after its `done`.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use noscat_client::{Client, Event};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc};

const FILE: &str = "control.json";
const TEXT_TIMEOUT: Duration = Duration::from_secs(90);

#[derive(Serialize, Deserialize)]
struct ControlFile {
    port: u16,
    token: String,
}

/// What a command asks the device to do.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Op {
    Members,
    Create { name: String },
    Invite { target: String },
    Join { inviter: String, timeout_secs: u64 },
    Remove { target: String },
    Leave { timeout_secs: u64 },
    Send { path: PathBuf, target: String },
    Text { target: String, text: String, clipboard: bool },
    Forward { target: String, local: SocketAddr, remote_port: u16 },
    Pipe { target: String },
    /// Open a terminal on a member; the connection then carries terminal
    /// frames (like `Pipe`, after `done`).
    Shell { target: String, cols: u16, rows: u16, term: String },
    /// Terminal sessions open here, or end one.
    Sessions { end: Option<u64> },
    Rename { name: String },
    /// List the mesh's relays, or add and remove some.
    Relays { add: Vec<String>, remove: Vec<String> },
    /// Access rules and recent requests.
    Access,
    /// Set a member's (or with `everyone`, the default) rule for a group,
    /// or with `once`, answer one request only.
    SetAccess { who: String, group: String, rule: String, once: bool },
    /// Drop a member's own access rules.
    ResetAccess { who: String },
    /// List the mesh's STUN servers, or add and remove some.
    Stun { add: Vec<String>, remove: Vec<String> },
    Private { private: bool },
    Qr,
    /// Devices that asked to join and are not members yet.
    Requests,
}

#[derive(Serialize, Deserialize)]
struct Request {
    token: String,
    op: Op,
}

/// A join request as `mesh requests` shows it.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RequestRow {
    pub npub: String,
    pub name: Option<String>,
    pub age_secs: u64,
}

/// A member row as `mesh members` prints it.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Row {
    pub npub: String,
    pub name: Option<String>,
    pub this_device: bool,
    pub online: bool,
    pub last_seen_secs: Option<u64>,
    #[serde(default)]
    pub reachable: bool,
    /// Data can flow to it right now (see `noscat_client::Member`).
    #[serde(default)]
    pub connected: bool,
}

/// One reply line.
#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum Reply {
    Line { text: String },
    Members { mesh: Option<String>, members: Vec<Row> },
    /// This device's pairing URI, to show as a QR.
    Qr { uri: String },
    /// Pending join requests, oldest first.
    Requests { requests: Vec<RequestRow> },
    Done,
    Error { error: String },
}

/// The running device as commands see it.
#[derive(Clone)]
pub struct Ctx {
    pub client: Client,
    pub events: broadcast::Sender<Event>,
}

impl Ctx {
    /// Wrap a started client: its events go to a broadcast every waiter
    /// and printer subscribes to.
    pub fn new(mut client: Client) -> Self {
        let (events, _) = broadcast::channel(1024);
        if let Some(rx) = client.events() {
            let tx = events.clone();
            std::thread::spawn(move || {
                for ev in rx {
                    let _ = tx.send(ev);
                }
            });
        }
        Self { client, events }
    }

    /// Run a blocking client call off the async threads (the client owns
    /// its own runtime and blocks on it).
    async fn blocking<T: Send + 'static>(
        &self,
        f: impl FnOnce(&Client) -> Result<T, noscat_client::ClientError> + Send + 'static,
    ) -> Result<T, String> {
        let c = self.client.clone();
        tokio::task::spawn_blocking(move || f(&c))
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())
    }
}

fn npub_of(target: &str) -> Result<String, String> {
    use nostr::nips::nip19::ToBech32 as _;
    let pk = noscat_client::parse_pairing_target(target)?;
    Ok(pk.to_bech32().unwrap_or_else(|_| pk.to_hex()))
}

fn line(out: &mpsc::UnboundedSender<Reply>, text: impl Into<String>) {
    let _ = out.send(Reply::Line { text: text.into() });
}

/// Do `op` on the device, narrating to `out`. `stop` ends long-running
/// ops (a forward) when the asker goes away. Not for `Pipe`.
pub async fn exec(
    ctx: &Ctx,
    op: Op,
    out: &mpsc::UnboundedSender<Reply>,
    stop: impl std::future::Future<Output = ()>,
) -> Result<(), String> {
    match op {
        Op::Members => {
            let (mesh, members) = ctx.blocking(|c| Ok((c.mesh_name(), c.members()))).await?;
            let members = members
                .into_iter()
                .map(|m| Row {
                    npub: m.npub,
                    name: m.name,
                    this_device: m.this_device,
                    online: m.online,
                    last_seen_secs: m.last_seen_secs,
                    reachable: m.reachable,
                    connected: m.connected,
                })
                .collect();
            let _ = out.send(Reply::Members { mesh, members });
        }
        Op::Create { name } => {
            let n = name.clone();
            ctx.blocking(move |c| c.create_mesh(&n)).await?;
            line(out, format!("mesh {name:?} created; invite devices with `noscat mesh invite <npub>`"));
        }
        Op::Invite { target } => {
            let t = target.clone();
            ctx.blocking(move |c| c.invite(&t)).await?;
            line(out, format!("invited {target}"));
        }
        Op::Join { inviter, timeout_secs } => {
            line(out, format!("waiting up to {timeout_secs}s for an invitation from {inviter} (they run `noscat mesh invite <this npub>`)"));
            let i = inviter.clone();
            ctx.blocking(move |c| c.join(&i, Duration::from_secs(timeout_secs))).await?;
            let name = ctx.blocking(|c| Ok(c.mesh_name())).await?.unwrap_or_default();
            line(out, format!("joined mesh {name:?}"));
        }
        Op::Remove { target } => {
            let t = target.clone();
            ctx.blocking(move |c| c.remove(&t)).await?;
            line(out, format!("removed {target}"));
        }
        Op::Relays { add, remove } => {
            if !add.is_empty() || !remove.is_empty() {
                let cur = ctx.blocking(|c| Ok(c.mesh_relays())).await?;
                if cur.is_empty() {
                    return Err("not in a mesh".into());
                }
                let norm = |r: &String| r.trim().trim_end_matches('/').to_string();
                let gone: Vec<String> = remove.iter().map(norm).collect();
                let mut next: Vec<String> = cur.iter().map(norm).filter(|r| !gone.contains(r)).collect();
                next.extend(add.iter().map(norm));
                if next.is_empty() {
                    return Err("a mesh needs at least one relay".into());
                }
                ctx.blocking(move |c| c.set_mesh_relays(&next)).await?;
            }
            let (relays, private) = ctx.blocking(|c| Ok((c.mesh_relays(), c.is_private()))).await?;
            if relays.is_empty() {
                return Err("not in a mesh".into());
            }
            let mode = if private {
                "private: devices use only these relays and log in to them"
            } else {
                "shared: devices also use their own relays"
            };
            line(out, format!("mesh relays ({mode}):"));
            for r in relays {
                line(out, format!("  {r}"));
            }
        }
        Op::Access => {
            let (defaults, devices, requests, members) = ctx
                .blocking(|c| Ok((c.access_defaults(), c.access_devices(), c.access_requests(), c.members())))
                .await?;
            let rules = |r: noscat_client::AccessRules| {
                format!("send {}, services {}, control {}", r.send.name(), r.services.name(), r.control.name())
            };
            line(out, format!("everyone: {}", rules(defaults)));
            for (npub, own) in devices {
                let own: Vec<String> = own.iter().map(|(g, r)| format!("{} {}", g.name(), r.name())).collect();
                line(out, format!("{}: {}", crate::ui::label(&members, &npub), own.join(", ")));
            }
            if !requests.is_empty() {
                line(out, "recent requests:");
            }
            for r in requests {
                use noscat_client::AccessOutcome as O;
                let what = match r.outcome {
                    O::Waiting => "waiting: `noscat allow` or `noscat deny` answers",
                    O::Allowed => "allowed",
                    O::Denied => "refused",
                    O::TimedOut => "not answered in time, refused",
                    O::NoOneToAsk => "refused: no app here to ask; allow it ahead of time",
                };
                let when = if r.age_secs < 5 { "now".to_string() } else { format!("{} ago", crate::ui::age(r.age_secs)) };
                line(out, format!("  {when}  {}  {}: {what}", crate::ui::label(&members, &r.peer), r.group.name()));
            }
        }
        Op::SetAccess { who, group, rule, once } => {
            use noscat_client::{AccessGroup, AccessRule};
            let g = AccessGroup::parse(&group).ok_or_else(|| format!("unknown access group {group:?}"))?;
            let r = match rule.as_str() {
                "allow" => AccessRule::Allow,
                "deny" => AccessRule::Deny,
                "ask" => AccessRule::Ask,
                _ => return Err(format!("unknown rule {rule:?}")),
            };
            if r == AccessRule::Ask && g != AccessGroup::Control {
                return Err("only control can ask; allow or deny the others".into());
            }
            if who.trim().eq_ignore_ascii_case("everyone") {
                if once {
                    return Err("--once needs a member, not everyone".into());
                }
                ctx.blocking(move |c| c.set_access(None, g, Some(r))).await?;
                line(out, format!("everyone: {} {}", g.name(), r.name()));
                return Ok(());
            }
            let members = ctx.blocking(|c| Ok(c.members())).await?;
            let npub = crate::ui::resolve(&members, &who)?;
            let name = crate::ui::label(&members, &npub);
            if once {
                let n = npub.clone();
                match r {
                    AccessRule::Allow => {
                        ctx.blocking(move |c| c.allow_once(&n, g)).await?;
                        line(out, format!("allowed {name} one {} request (the waiting one, or its next)", g.name()));
                    }
                    AccessRule::Deny => {
                        let was = ctx.blocking(move |c| c.answer_waiting(&n, g, false)).await?;
                        line(out, if was { format!("refused {name}'s waiting {} request", g.name()) } else { format!("nothing from {name} was waiting") });
                    }
                    AccessRule::Ask => return Err("--once is for allow and deny".into()),
                }
                return Ok(());
            }
            let n = npub.clone();
            ctx.blocking(move |c| {
                c.set_access(Some(&n), g, Some(r))?;
                // The new rule also answers a request waiting right now.
                if r != AccessRule::Ask {
                    c.answer_waiting(&n, g, r == AccessRule::Allow)?;
                }
                Ok(())
            })
            .await?;
            line(out, format!("{name}: {} {}", g.name(), r.name()));
        }
        Op::ResetAccess { who } => {
            let members = ctx.blocking(|c| Ok(c.members())).await?;
            let npub = crate::ui::resolve(&members, &who)?;
            let n = npub.clone();
            ctx.blocking(move |c| c.reset_access(&n)).await?;
            line(out, format!("{}: the defaults apply again", crate::ui::label(&members, &npub)));
        }
        Op::Stun { add, remove } => {
            let in_mesh = ctx.blocking(|c| Ok(c.in_mesh())).await?;
            if !in_mesh {
                return Err("not in a mesh".into());
            }
            if !add.is_empty() || !remove.is_empty() {
                let canon = |s: &String| noscat_core::marmot::codec::canonical_stun(s).ok_or_else(|| format!("not an ip:port (no hostnames): {}", s.trim()));
                let gone = remove.iter().map(canon).collect::<Result<Vec<_>, _>>()?;
                let mut next: Vec<String> = ctx.blocking(|c| Ok(c.mesh_stun())).await?;
                next.retain(|s| !gone.contains(s));
                next.extend(add.iter().map(canon).collect::<Result<Vec<_>, _>>()?);
                ctx.blocking(move |c| c.set_mesh_stun(&next)).await?;
            }
            let (stun, private) = ctx.blocking(|c| Ok((c.mesh_stun(), c.is_private()))).await?;
            if stun.is_empty() {
                line(
                    out,
                    if private {
                        "no mesh STUN servers: devices of this private mesh use none and connect through the reachable member"
                    } else {
                        "no mesh STUN servers: devices use public STUN servers"
                    },
                );
            } else {
                line(out, "mesh STUN servers (each device uses them from its next start):");
                for s in stun {
                    line(out, format!("  {s}"));
                }
            }
        }
        Op::Private { private } => {
            ctx.blocking(move |c| c.set_private(private)).await?;
            if private {
                let relays = ctx.blocking(|c| Ok(c.mesh_relays())).await?;
                line(out, format!("the mesh is private: its devices now use only {}", relays.join(", ")));
                line(out, "new devices join by scanning a member's QR (it now names these relays)");
            } else {
                line(out, "the mesh is shared: its devices use their own relays too");
            }
        }
        Op::Requests => {
            let (in_mesh, list) = ctx.blocking(|c| Ok((c.mesh_name().is_some(), c.join_requests()))).await?;
            if !in_mesh {
                return Err("not in a mesh".into());
            }
            let requests =
                list.into_iter().map(|r| RequestRow { npub: r.npub, name: r.name, age_secs: r.age_secs }).collect();
            let _ = out.send(Reply::Requests { requests });
        }
        Op::Qr => {
            let uri = ctx.blocking(|c| Ok(c.pairing_uri())).await?;
            let _ = out.send(Reply::Qr { uri });
        }
        Op::Leave { timeout_secs } => {
            ctx.blocking(move |c| c.leave(Duration::from_secs(timeout_secs))).await?;
            line(out, "left the mesh");
        }
        Op::Send { path, target } => {
            let mut rx = ctx.events.subscribe();
            let id = ctx.client.send_file(path.clone(), &target);
            let mut last_tenth = None;
            loop {
                match rx.recv().await {
                    Ok(Event::TransferProgress { id: i, sent, total, .. }) if i == id => {
                        let tenth = if total == 0 { 10 } else { sent * 10 / total };
                        if last_tenth != Some(tenth) {
                            last_tenth = Some(tenth);
                            line(out, format!("{}% of {}", tenth * 10, path.display()));
                        }
                    }
                    Ok(Event::TransferDone { id: i, peer, .. }) if i == id => {
                        line(out, format!("sent {} to {peer}", path.display()));
                        break;
                    }
                    Ok(Event::TransferFailed { id: i, error, .. }) if i == id => return Err(error),
                    Ok(Event::TransferCancelled { id: i, .. }) if i == id => return Err("cancelled".into()),
                    Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(e) => return Err(e.to_string()),
                }
            }
        }
        Op::Text { target, text, clipboard } => {
            let npub = npub_of(&target)?;
            let mut rx = ctx.events.subscribe();
            if clipboard {
                ctx.client.send_clipboard(&target, &text);
            } else {
                ctx.client.send_chat(&target, &text);
            }
            let wait = async {
                loop {
                    match rx.recv().await {
                        Ok(Event::ChatDelivered { peer }) if peer == npub => return Ok(()),
                        Ok(Event::ChatFailed { peer, error }) if peer == target || peer == npub => return Err(error),
                        Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                        Err(e) => return Err(e.to_string()),
                    }
                }
            };
            tokio::time::timeout(TEXT_TIMEOUT, wait)
                .await
                .map_err(|_| "no answer from the member".to_string())??;
            line(out, format!("delivered to {npub}"));
        }
        Op::Forward { target, local, remote_port } => {
            let mut rx = ctx.events.subscribe();
            let id = ctx.client.forward_port(&target, local, remote_port);
            let to = if remote_port == 0 { "its default service".to_string() } else { format!("port {remote_port}") };
            line(out, format!("forwarding tcp/{local} to {target} ({to}); Ctrl-C stops"));
            let stopped = async {
                loop {
                    match rx.recv().await {
                        Ok(Event::ForwardStopped { id: i, error }) if i == id => return error,
                        Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                        Err(e) => return Some(e.to_string()),
                    }
                }
            };
            tokio::select! {
                err = stopped => if let Some(e) = err { return Err(e) },
                () = stop => { ctx.client.cancel_forward(id); }
            }
        }
        Op::Rename { name } => {
            let n = name.clone();
            ctx.blocking(move |c| {
                c.set_device_name(&n);
                Ok::<_, noscat_client::ClientError>(())
            })
            .await?;
            line(out, format!("this device is now {name:?}"));
        }
        Op::Pipe { .. } | Op::Shell { .. } => return Err("pipe and shell are not exec ops".into()),
        Op::Sessions { end } => {
            let (sessions, members) = ctx.blocking(|c| Ok((c.terminal_sessions(), c.members()))).await?;
            if let Some(id) = end {
                if !ctx.blocking(move |c| Ok(c.end_terminal(id))).await? {
                    return Err(format!("no session {id} is open"));
                }
                line(out, format!("ended session {id}"));
                return Ok(());
            }
            if sessions.is_empty() {
                line(out, "no terminal sessions are open here");
            }
            for s in sessions {
                line(out, format!("  {}  {}  open {}", s.id, crate::ui::label(&members, &s.peer), crate::ui::age(s.secs)));
            }
        }
    }
    Ok(())
}

// ---- server ---------------------------------------------------------------

/// Serve the control channel for `ctx` until the process exits. Writes
/// `<dir>/control.json`; [`remove`] deletes it on the way out.
pub async fn serve(ctx: Ctx, dir: &Path) -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let token = hex::encode(rand::random::<[u8; 32]>());
    let file = serde_json::to_vec(&ControlFile { port, token: token.clone() })?;
    noscat_core::fsutil::write_private_atomic(&dir.join(FILE), &file)
        .with_context(|| format!("writing {}", dir.join(FILE).display()))?;
    tokio::spawn(async move {
        while let Ok((conn, _)) = listener.accept().await {
            let ctx = ctx.clone();
            let token = token.clone();
            tokio::spawn(async move {
                if let Err(e) = handle(ctx, conn, &token).await {
                    tracing::debug!("control: {e}");
                }
            });
        }
    });
    Ok(())
}

/// Remove `control.json` (best effort; a stale file is detected anyway).
pub fn remove(dir: &Path) {
    let _ = std::fs::remove_file(dir.join(FILE));
}

async fn send(w: &mut (impl tokio::io::AsyncWrite + Unpin), r: &Reply) -> std::io::Result<()> {
    let mut b = serde_json::to_vec(r).map_err(std::io::Error::other)?;
    b.push(b'\n');
    w.write_all(&b).await
}

async fn handle(ctx: Ctx, conn: TcpStream, token: &str) -> Result<()> {
    let (r, mut w) = conn.into_split();
    let mut r = BufReader::new(r);
    let mut first = String::new();
    r.read_line(&mut first).await?;
    let req: Request = serde_json::from_str(&first)?;
    if req.token != token {
        send(&mut w, &Reply::Error { error: "bad token".into() }).await?;
        return Ok(());
    }
    if let Op::Shell { target, cols, rows, term } = req.op {
        let (lines_tx, mut lines_rx) = mpsc::unbounded_channel();
        let opening = open_shell(&ctx, target, cols, rows, term, move |r| {
            let _ = lines_tx.send(r);
        });
        tokio::pin!(opening);
        let res = loop {
            tokio::select! {
                res = &mut opening => break res,
                Some(r) = lines_rx.recv() => { send(&mut w, &r).await?; }
            }
        };
        while let Ok(r) = lines_rx.try_recv() {
            send(&mut w, &r).await?;
        }
        match res {
            Ok(mut stream) => {
                send(&mut w, &Reply::Done).await?;
                let mut conn = r.into_inner().reunite(w)?;
                let _ = tokio::io::copy_bidirectional(&mut conn, &mut stream).await;
            }
            Err(error) => send(&mut w, &Reply::Error { error }).await?,
        }
        return Ok(());
    }
    if let Op::Pipe { target } = req.op {
        let c = ctx.client.clone();
        let stream = tokio::task::spawn_blocking(move || c.connect(&target)).await?;
        match stream {
            Ok(mut stream) => {
                send(&mut w, &Reply::Done).await?;
                let mut conn = r.into_inner().reunite(w)?;
                let _ = tokio::io::copy_bidirectional(&mut conn, &mut stream).await;
            }
            Err(e) => send(&mut w, &Reply::Error { error: e.to_string() }).await?,
        }
        return Ok(());
    }
    let (tx, mut rx) = mpsc::unbounded_channel();
    // The asker hanging up (Ctrl-C) stops a long-running op.
    let gone = async move {
        let mut sink = Vec::new();
        let _ = tokio::io::AsyncReadExt::read_to_end(&mut r, &mut sink).await;
    };
    let work = async {
        let res = exec(&ctx, req.op, &tx, gone).await;
        let _ = tx.send(match res {
            Ok(()) => Reply::Done,
            Err(error) => Reply::Error { error },
        });
        drop(tx);
    };
    let pump = async {
        while let Some(reply) = rx.recv().await {
            if send(&mut w, &reply).await.is_err() {
                break;
            }
        }
    };
    tokio::join!(work, pump);
    Ok(())
}

/// Open a terminal on `target` (a member's name or npub), narrating the
/// wait for its approval through `show`.
pub async fn open_shell(
    ctx: &Ctx,
    target: String,
    cols: u16,
    rows: u16,
    term: String,
    mut show: impl FnMut(Reply) + Send,
) -> Result<noscat_client::MeshStream, String> {
    let members = ctx.blocking(|c| Ok(c.members())).await?;
    let npub = crate::ui::resolve(&members, &target)?;
    let name = crate::ui::label(&members, &npub);
    if !members.iter().any(|m| m.npub == npub && m.control) {
        show(Reply::Line { text: format!("{name} does not say it offers a terminal; trying anyway") });
    }
    let mut events = ctx.events.subscribe();
    let n = npub.clone();
    let opening = ctx.blocking(move |c| c.open_terminal(&n, cols, rows, &term));
    tokio::pin!(opening);
    loop {
        tokio::select! {
            res = &mut opening => return res,
            ev = events.recv() => {
                if let Ok(Event::TerminalWaiting { peer }) = ev {
                    if peer == npub {
                        show(Reply::Line { text: format!("waiting for {name} to approve (up to a minute)") });
                    }
                }
            }
        }
    }
}

// ---- asking side ------------------------------------------------------------

/// A connection to the running device for `dir`, if one answers.
pub async fn connect(dir: &Path) -> Option<(TcpStream, String)> {
    let file: ControlFile = serde_json::from_slice(&std::fs::read(dir.join(FILE)).ok()?).ok()?;
    let conn = tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(("127.0.0.1", file.port)))
        .await
        .ok()?
        .ok()?;
    Some((conn, file.token))
}

/// Run `op` on the device behind `conn`, printing its narration through
/// `show`. Returns the members for a `Members` op.
pub async fn ask(
    conn: TcpStream,
    token: String,
    op: Op,
    mut show: impl FnMut(Reply),
) -> Result<()> {
    let pipe = matches!(op, Op::Pipe { .. });
    let shell = matches!(op, Op::Shell { .. });
    let (r, mut w) = conn.into_split();
    let mut req = serde_json::to_vec(&Request { token, op })?;
    req.push(b'\n');
    w.write_all(&req).await?;
    let mut r = BufReader::new(r);
    let mut buf = String::new();
    loop {
        buf.clear();
        if r.read_line(&mut buf).await? == 0 {
            bail!("the running noscat closed the connection");
        }
        match serde_json::from_str::<Reply>(&buf)? {
            Reply::Done => break,
            Reply::Error { error } => bail!("{error}"),
            other => show(other),
        }
    }
    if shell {
        // The connection now carries the session's terminal frames.
        let conn = r.into_inner().reunite(w)?;
        let code = crate::shell::run(conn).await?;
        std::process::exit(code);
    }
    if pipe {
        // The connection is now the byte stream to the member.
        let mut conn = r.into_inner().reunite(w)?;
        let mut stdio = tokio::io::join(tokio::io::stdin(), tokio::io::stdout());
        tokio::io::copy_bidirectional(&mut conn, &mut stdio).await?;
    }
    Ok(())
}
