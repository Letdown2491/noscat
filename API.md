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
membership, data plane and an event stream. 0.5 is a fresh start: it
reads no 0.4 state, and the CLI and apps keep 0.5 state in new
locations, so every device gets a new identity.

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

`set_storage_key(Option<[u8; 32]>)` seals the device's secret files
(`identity.nsec`, `mesh-state.json`) at rest with XChaCha20-Poly1305 from
then on; plain files migrate on their next write. It is process-wide:
call it once at start, before any client or device-directory helper. The
apps keep the key in the platform keystore (Android Keystore, the desktop
keyring); the CLI writes plain files. A sealed file opened without the
right key is an error ("... is encrypted ..."), never treated as missing,
so no fresh identity replaces it; losing the key loses the device, and
only deleting its directory (Forget mesh) recovers.

### Client

`identity_npub(&IdentitySource)` resolves an identity (creating the file)
without starting anything.

Also exported: `parse_pairing_target(&str)` (a QR's `noscat:` URI, a bare
npub or hex key to a public key; what the join screens use to validate
input), `parse_pairing_relays(&str)` and `pairing_uri(npub, relays)` (a
private mesh's relay hints in a pairing URI), `DEFAULT_RELAYS` / `default_relays()`, `MAX_INCOMING_BYTES`
(64 GiB) and `DEFAULT_LISTEN_PORT` (41641, used when reachable).

`Client::start(config) -> Result<Client, ClientError>` starts the device
right away (relay connections, key package, data plane). It blocks for a
few seconds; call it from a worker thread, never from inside an async
runtime. Cloning shares the device; dropping the last clone stops it and
releases the directory, so a new `Client` can start on it right away (the
apps join with one client, drop it, then start their long-running one).
Only one `Client` may run per state directory, across processes too:
`start` locks `<dir>/lock` and fails with `ClientError::Busy` while another
client holds it, in this process or another. `Client::running(dir)`
returns the one running in this process. `Client` is `Send + Sync`;
dropping it from async code is safe.

Mesh:

| Method | Returns | Contract |
|---|---|---|
| `npub()` | `&str` | This device's address. Cheap. |
| `in_mesh()` / `mesh_name()` | `bool` / `Option<String>` | |
| `device_name()` | `String` | This device's name, as members see it. |
| `set_device_name(name)` | `()` | Rename; blocks until the advert carrying it is published, so members see it within seconds. Blank is ignored. The caller saves the name for the next start (config `device_name`). |
| `create_mesh(name)` | `()` | New mesh with this device as the only member. |
| `invite(target)` | `()` | Add a device (npub or `noscat:` URI). The device must be running or waiting in `join`. |
| `join(inviter, timeout)` | `()` | Wait for the inviter's invitation and join. The scanned QR (the inviter) is the trust anchor: invitations from anyone else are ignored. Pass the scanned code whole: when it names relays (`?relay=`, a private mesh's), the join goes through them alone, logged in (NIP-42). |
| `mesh_relays()` / `is_private()` | `Vec<String>` / `bool` | The mesh's relays; whether it is private. |
| `set_mesh_relays(relays)` | `()` | Replace the mesh's relays (1 to 16 `wss://` URLs). Every member moves to the new list. |
| `set_private(bool)` | `()` | Make the mesh private (every device uses only the mesh's relays, logs in to them with NIP-42, leaves its own and the public ones) or shared again. noscat logs in to no other relay. |
| `pairing_uri()` | `String` | What the pairing QR shows: `noscat:<npub>`, plus `?relay=` for each of a private mesh's relays. |
| `remove(target)` | `()` | Remove a member. Every member is an admin and may do this. |
| `leave(timeout)` | `()` | Leave; waits for another member to commit it. With none in time it forgets the mesh locally anyway: the request stays on the relays and the next member to come online completes it. The last member just forgets the mesh. When there is nothing to leave, the error message contains "this device is not in a mesh". |
| `members()` | `Vec<Member>` | `npub, name, admin, this_device, online, last_seen_secs, reachable, connected`. `online`: its advert arrived over the relays recently, which says nothing about whether data can reach it. `connected`: data can flow to it now (a direct link or a live connection, possibly relayed). While `up` or `expose` runs, the client keeps a connection to every online member (dialing every 30 s), so online but not connected means seen but unreachable. `reachable`: its latest advert says it is reachable from the internet. A `Roster` event follows every connection change. |
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
| `send_file(path, target)` | `u64` | Async; returns the transfer id that its `Transfer*` events carry. Resumes a partial the receiver kept. |
| `cancel_transfer(target, path)` | `bool` | The receiver keeps its partial for a resume. |
| `send_chat(target, text)` / `send_clipboard(target, text)` | `()` | Delivery is `ChatDelivered` or `ChatFailed`. Text up to 64 KiB. |
| `forward(target, local)` | `u64` | Listen on `local`; each TCP connection goes to the member's default service. |
| `forward_port(target, local, remote_port)` | `u64` | Same, to a port the member serves (`serve_port`). |
| `list_forwards()` / `cancel_forward(id)` | `Vec<ForwardInfo>` / `bool` | `ForwardInfo { id, target, local, remote_port }` (`remote_port` 0 = default service). `cancel_forward` is confirmed by `ForwardStopped`. |

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
| `TransferStarted` | `id, peer, name, size, incoming, path` | A transfer began, either direction; `id` names it in every later transfer event. `path` is the source of a send, `None` on a receive. |
| `TransferDone` | `id, peer, path` | Whole file verified (sha256) and in place. On send, `path` is the source; on receive, the final file, whose name may differ from the sent one when it was taken. |
| `TransferPartial` | `id, peer, path` | Receive ended without a whole file; the `.noscat-part` resumes on resend. |
| `TransferProgress` | `id, peer, path, sent, total` | Both directions, at most one event per percent. `path` is the source on a send, the `.noscat-part` on a receive. |
| `TransferFailed` | `id, peer, path, error` | `path` is `None` on a receive. |
| `TransferCancelled` | `id, peer, path` | A send cancelled by this side. |
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
| `JoinRequest` | `peer, name` | A device that scanned this device's QR (or otherwise knows its npub) asks to be invited: prompt, then `invite(peer)`. Only while in a mesh; at most once per request. |

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
Match on the variant, show the display string. `Busy` means another
client holds the state directory.

---

## noscat-ffi (Kotlin via UniFFI, Swift later)

A device directory holds one device (`identity.nsec`, mesh state) and at
most one device runs per directory. The `mesh_*` functions use the app's
running `NoscatClient` for that directory when there is one (pass the
same `mesh_dir`), and otherwise run the device just for the call.

### Functions

| Function | Contract |
|---|---|
| `set_storage_key(key?)` | Seal secret files with this 32-byte key (see `set_storage_key` above). Call first. Throws for a key of the wrong length. |
| `generate_identity()` | New `Identity { npub, secret_hex }`. |
| `identity_from_secret(secret)` | Restore from hex or nsec. |
| `mesh_prepare(dir, owner?, relays?)` | This directory's npub, creating `identity.nsec` if missing. `owner` is unused (kept for call compatibility). |
| `mesh_join(dir, timeout_secs, owner_npub, relays?)` | Wait for an invitation from `owner_npub` (bare npub or `noscat:` URI) and join; the inviter is sent a join request. Returns the members. A timeout is the error "no invitation arrived in time". |
| `mesh_members(dir, relays?)` | The members. Presence (`online`, `last_seen_secs`) is only known while a client runs for `dir`. |
| `mesh_sync(dir, wait_secs, relays?)` | The members after catching up: immediate when a client runs for `dir`, else after running the device for `wait_secs`. |
| `mesh_create(dir, name, relays?)` | New mesh with this device as the only member. |
| `mesh_invite(dir, npub, relays?)` | Add a device; it must be running or in `mesh_join`. |
| `mesh_remove(dir, npub, relays?)` | Remove a member. |
| `mesh_leave(dir, timeout_secs, relays?)` | Leave; waits for another member to complete it (see `leave` above for the timeout case). Deleting `dir` afterwards, once no client runs on it, makes the next join a new device. |

0.4's `mesh_resend` is gone: there is no owner journal to replay.

### Records

- `ClientConfig { identity_secret?, relays?, mesh_dir?, device_name?, listen_port? }`. With `mesh_dir` and no `identity_secret`, the client uses the
  dir's `identity.nsec`; apps should do that rather than read the file,
  which is sealed under a storage key.
  `listen_port` None = any free port (0.4 defaulted to 41641).
- `MeshMember { npub, name?, last_seen_secs?, online, admin, this_device, reachable, connected }` (see `members()`).
  0.4's `is_owner` is gone: every device is an admin.
- `ForwardInfo { id, target, local }` (`local` as a string, e.g.
  `"127.0.0.1:8080"`).
- `Identity { npub, secret_hex }`.
- Errors are `NoscatException.Failed(message)` (one flat variant); show
  the message.

### NoscatClient

`NoscatClient(config, listener)`, a mirror of the Rust `Client`. The
`listener` implements the `EventListener` callback interface
(`onEvent(event)`). Releasing the last reference stops the device and
frees its directory, like dropping a Rust `Client`. In Kotlin that means
`close()` (the class is `AutoCloseable`): an object merely dropped keeps
the device running until the garbage collector frees it, and a new client
on the same directory fails with `Busy` until then.

`npub()`, `meshName()`, `deviceName()`, `setDeviceName(name)` (blocking), `members()`, `invite(npub)`, `remove(npub)`,
`networkChanged()`, `forward(target, localPort)`, `listForwards()`,
`cancelForward(id)`, `expose(toHost, toPort)`, `servePort(port, enabled)`,
`sendFile(path, target)` (returns the transfer id), `cancelTransfer(path, target)`,
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
`TransferStarted` (with `path: String?`) and an `id` on every transfer
event, `MeshJoined`, `Roster`, `MemberSeen`, `MeshChangeUndone`, `MeshLeft`,
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
