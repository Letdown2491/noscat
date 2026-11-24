# API.md - the app-facing API contract

The public surface the client apps consume: `noscat-client` (Rust, embedded
directly by noscat-desktop) and `noscat-ffi` (UniFFI, consumed by
noscat-android and later mobile platforms).

> **Current as of 0.5.0.** If your `Cargo.lock` pins a newer version than
> this stamp, distrust this file and read the crate source; if you change
> the public surface, update this file in the same commit.

Rules that keep this file true:

- Any change to a `pub` item of `noscat-client` or `noscat-ffi` updates
  this file in the same commit. Semantic changes (defaults, threading,
  timeouts) count even when signatures do not.
- Bump the stamp on every release.
- The wire protocol is NOT this document: see `docs/nip-noscat.md`.
- The desktop app embeds `noscat-client` directly and must not reach into
  `noscat-core` beyond the items listed here.

## Crate map

| Crate | Consumers | Contents |
|---|---|---|
| `noscat-client` | noscat-desktop (direct dep), the CLI | `Client`, `Event`, `Member`, config, identity sources |
| `noscat-ffi` | noscat-android (UniFFI bridge) | `NoscatClient`, `Event`, mesh functions, identity helpers |
| `noscat-core` | private (client + ffi + cli) | FIPS data plane, QUIC streams, Marmot mesh group, device runtime, app protocols |

---

## noscat-client (Rust)

A `Client` is one running device: identity, state directory, mesh
membership, data plane and an event stream. 0.5 is a fresh start: no 0.4
state is read, and a 0.4 identity file still works as an identity but
its old mesh is not carried over.

### Identity and config

```rust
pub enum IdentitySource {
    Ephemeral,       // fresh keypair per process
    Secret(String),  // hex secret or nsec1...
    File(PathBuf),   // created 0600 on first use; refused if group/world readable
}

pub struct ClientConfig {
    pub identity: IdentitySource,              // default: Ephemeral
    pub relays: Option<Vec<String>>,           // None = DEFAULT_RELAYS
    pub listen: Option<SocketAddr>,            // FIPS UDP bind; None = any port (41641 when reachable)
    pub mesh_dir: Option<PathBuf>,             // device state dir; None = temp dir, gone on drop
    pub device_name: Option<String>,           // shown to members (advert)
    pub reachable: Option<Option<SocketAddr>>, // Some(None) = STUN, Some(Some(a)) = advertise a
    pub lan_discovery: bool,                   // default: true (mDNS)
    pub max_incoming_bytes: Option<u64>,       // None = MAX_INCOMING_BYTES (64 GiB)
    pub static_peers: Vec<(String, SocketAddr)>, // known addresses (npub or hex)
    pub stun_servers: Option<Vec<String>>,     // None = data plane defaults
}
```

Every mesh needs at least one reachable member (a port forward, a VPS, a
public IPv6 address); members behind NAT reach each other through it.

### Client

`identity_npub(&IdentitySource)` resolves an identity (creating the file)
without starting anything.

`Client::start(config) -> Result<Client, ClientError>` starts the device
right away (relay connections, key package, data plane). It blocks for a
few seconds; call it from a worker thread, never from inside an async
runtime. Cloning shares the device; dropping the last clone stops it.
Only one `Client` may run per state directory, across processes too:
`start` locks `<dir>/lock` and fails with `ClientError::Busy` when another
process holds it. `Client::running(dir)` returns the one running in this
process. `Client` is `Send + Sync`; dropping it from async code is safe.

Mesh:

| Method | Returns | Contract |
|---|---|---|
| `npub()` | `&str` | This device's address. Cheap. |
| `in_mesh()` / `mesh_name()` | `bool` / `Option<String>` | |
| `create_mesh(name)` | `()` | New mesh with this device as the only member. |
| `invite(target)` | `()` | Add a device (npub or `noscat:` URI). The device must be running or waiting in `join`. |
| `join(inviter, timeout)` | `()` | Wait for the inviter's invitation and join. The scanned QR (the inviter) is the trust anchor: invitations from anyone else are ignored. |
| `remove(target)` | `()` | Remove a member. Every member is an admin and may do this. |
| `leave(timeout)` | `()` | Leave; waits for another member to commit it. The last member just forgets the mesh. |
| `members()` | `Vec<Member>` | `npub, name, admin, this_device, online, last_seen_secs`. |
| `member_age_secs(npub)` / `member_online(npub)` | `Option<u64>` / `bool` | Presence from adverts (sent every 2 minutes, fresh for 10). |
| `network_changed()` | `()` | Re-check paths after a network switch. |
| `events()` | `Option<Receiver<Event>>` | Take the receiver once; pump it forever. |

Receiving:

| Method | Returns | Contract |
|---|---|---|
| `up(out_dir, bridge_to)` | `SocketAddr` | Accept files into `out_dir`; bridge default-service streams to `bridge_to` when set. Emits `Listening`. |
| `receive_file(out_dir)` | `()` | Accept files into `out_dir` without touching the bridge. |
| `expose(to)` | `SocketAddr` | Bridge default-service streams to the TCP service `to`. Emits `Listening`. |
| `serve_port(port, enabled)` | `()` | Let members forward to `127.0.0.1:port` here by number. |
| `serve_stdio()` | `()` | Netcat mode: bridge the first default-service stream to stdio. Blocks. |

Sending:

| Method | Returns | Contract |
|---|---|---|
| `connect(target)` | `MeshStream` | `AsyncRead + AsyncWrite` to the member's default service. |
| `pipe_stdio(target)` | `()` | Netcat mode, dial side. Blocks. |
| `send_file(path, target)` | `()` | Async; progress and outcome as events. Resumes a partial the receiver kept. |
| `cancel_transfer(target, path)` | `bool` | The receiver keeps its partial for a resume. |
| `send_chat(target, text)` / `send_clipboard(target, text)` | `()` | Delivery is `ChatDelivered` or `ChatFailed`. Text up to 64 KiB. |
| `forward(target, local)` | `u64` | Listen on `local`; each TCP connection goes to the member's default service. |
| `forward_port(target, local, remote_port)` | `u64` | Same, to a port the member serves (`serve_port`). |
| `list_forwards()` / `cancel_forward(id)` | `Vec<ForwardInfo>` / `bool` | `cancel_forward` is confirmed by `ForwardStopped`. |

Scope: only members of this device's mesh can reach it or be reached.
Streams from anyone else never get past the data plane. A device that is
in no mesh can do nothing but create, join and be invited.

### Event (exhaustive; UIs must match every variant)

Peers are bech32 npubs.

| Variant | Fields | Meaning |
|---|---|---|
| `Listening` | `npub, addr` | Receiving is set up; the pairing QR banner belongs here. |
| `TunnelUp` | `peer` | A connection with a member is up (dialed or accepted). |
| `TunnelClosed` | `peer, error` | It ended; `error` set when not a clean close. |
| `TransferDone` | `peer, path` | Whole file verified (sha256) and in place. On send, `path` is the source. |
| `TransferPartial` | `peer, path` | Receive ended without a whole file; the `.noscat-part` resumes on resend. |
| `TransferProgress` | `peer, path, sent, total` | Sends only, one event per percent. |
| `TransferFailed` | `peer, path, error` | `path` is `None` for a receive that never started. |
| `TransferCancelled` | `peer, path` | Cancelled by this side. |
| `ForwardStopped` | `id, error` | Drop it from the UI list. |
| `ChatMessage` | `peer, text` | |
| `ChatDelivered` | `peer` | The member acknowledged the text. |
| `ChatFailed` | `peer, error` | Keep the optimistic copy, mark undelivered. |
| `Clipboard` | `peer, text` | Put `text` on the system clipboard. |
| `Stopped` | `what, error` | A background operation stopped. |
| `MeshJoined` | `name` | This device is in a mesh now (created or joined). |
| `Roster` | `members` | The member list changed. |
| `MemberSeen` | `peer, name` | A member's advert arrived. |
| `MeshChangeUndone` | | A membership change of ours lost a race with another member's; retry it. |
| `MeshLeft` | | Removed, or left. |
| `JoinRequest` | `peer, name` | A device that scanned this device's QR asks to be invited: prompt, then `invite(peer)`. |

0.4's `Incoming` is gone: inbound streams are always handled by the
client. `TunnelUp` no longer carries an address.

Delivery contracts:

- Events arrive on a client-owned thread. UIs hop to their main thread
  before touching UI state.
- The channel is unbounded; drain it continuously anyway. `Event` is
  `Clone`, so a UI can fan it out.
- Nothing in the client prints; logging goes through `tracing`.

### Errors

`ClientError`: `Identity(String) | Mesh(String) | Io(io::Error) | Stream(String) | Busy(PathBuf)`.
Match on the variant, show the display string.

---

## noscat-ffi (Kotlin via UniFFI, Swift later)

A device directory holds one device (`identity.nsec`, mesh state) and at
most one device runs per directory. The `mesh_*` functions use the app's
running `NoscatClient` for that directory when there is one (pass the
same `mesh_dir`), and otherwise run the device just for the call.

### Functions

| Function | Contract |
|---|---|
| `generate_identity()` | New `Identity` record. |
| `identity_from_secret(secret)` | Restore from hex or nsec. |
| `mesh_prepare(dir, owner?, relays?)` | This directory's npub, creating `identity.nsec` if missing. `owner` is unused (kept for call compatibility). |
| `mesh_join(dir, timeout_secs, owner_npub, relays?)` | Wait for an invitation from `owner_npub` (bare npub or `noscat:` URI) and join; the inviter is sent a join request. Returns the members. A timeout is the error "no invitation arrived in time". |
| `mesh_members(dir, relays?)` | The members. Presence (`online`, `last_seen_secs`) is only known while a client runs for `dir`. |
| `mesh_sync(dir, wait_secs, relays?)` | The members after catching up: immediate when a client runs for `dir`, else after running the device for `wait_secs`. |
| `mesh_create(dir, name, relays?)` | New mesh with this device as the only member. |
| `mesh_invite(dir, npub, relays?)` | Add a device; it must be running or in `mesh_join`. |
| `mesh_remove(dir, npub, relays?)` | Remove a member. |
| `mesh_leave(dir, timeout_secs, relays?)` | Leave; waits for another member to complete it. |

0.4's `mesh_resend` is gone: there is no owner journal to replay.

### Records

- `ClientConfig { identity_secret?, relays?, mesh_dir?, device_name?, listen_port? }`.
  `listen_port` None = any free port (0.4 defaulted to 41641).
- `MeshMember { npub, name?, last_seen_secs?, online, admin, this_device }`.
  0.4's `is_owner` is gone: every device is an admin.
- `ForwardInfo { id, target, local }`.

### NoscatClient

`NoscatClient(config, listener)`, a mirror of the Rust `Client`:

`npub()`, `meshName()`, `members()`, `invite(npub)`, `remove(npub)`,
`networkChanged()`, `forward(target, localPort)`, `listForwards()`,
`cancelForward(id)`, `expose(toHost, toPort)`, `servePort(port, enabled)`,
`sendFile(path, target)`, `cancelTransfer(path, target)`,
`receiveFile(outDir)`, `sendChat(target, text)`,
`sendClipboard(target, text)`, `up(outDir, bridgePort?)`.

Threading contract (the Android app's rules 5 and 6, restated because they
are the ones apps keep violating):

- `EventListener.on_event` fires on a background thread: hop to main
  before touching UI.
- Never call any `NoscatClient` method or `mesh_*` function on the main
  thread: even cheap getters can block behind relay work and ANR.

### Event (UniFFI enum, exhaustive when-match required)

The Rust `Event` set with `path: String` instead of `PathBuf`,
`Listening { npub, port }` instead of a SocketAddr, `TransferFailed`
without `path`, and `Roster { members: List<MeshMember> }`. New in 0.5:
`MeshJoined`, `Roster`, `MemberSeen`, `MeshChangeUndone`, `MeshLeft`,
`JoinRequest { peer, name? }` (a device that scanned this one's QR asks
to be invited: show a prompt, then `invite(peer)`).

---

## Mesh behavior contracts (both surfaces)

- One device per state directory: `mesh-state.json` (group keys and
  membership, written 0600 and atomically) and `relay-sync.json` (where
  the relay subscription resumes). The identity lives wherever
  `IdentitySource` says; the CLI and apps keep `identity.nsec` next to
  the state.
- A mesh is a Marmot group (MLS). noscat meshes interoperate with
  White Noise and other MDK clients: a White Noise account can be invited
  into a mesh and a noscat device into a White Noise group. Only noscat
  devices use the data plane.
- Every member is an admin. Two members changing membership within
  seconds of each other converge on one result; the loser sees
  `MeshChangeUndone` (ADR 0007).
- `join` accepts only an invitation from the named inviter.
- Adverts (name, presence) travel inside the group, so relays see neither.

## Versioning

- Crates ship in lockstep; the workspace version is the release version.
- Breaking changes to any `pub` item listed here are allowed between
  releases but MUST land in the same commit as this file's update, and
  the app repos get an adoption note on their tracking issue.
- `cargo semver-checks` runs in the release workflow as a mechanical
  backstop for signature changes.
