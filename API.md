# API.md: the app-facing API contract

The public surface the client apps consume: `noscat-client` (Rust, embedded
directly by noscat-desktop) and `noscat-ffi` (UniFFI, consumed by
noscat-android and later mobile platforms).

> **Current as of 0.7.0.** If your `Cargo.lock` pins a newer version than
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
membership, data plane and an event stream.

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
    pub join_relays: Vec<String>,              // a pairing code's relays, when started to join through them
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

`join_relays`: a client started in order to join with a code that names
relays (`parse_pairing_relays(code)`, a private mesh's) passes them here.
Until the join ends it uses only those, from its first moment, so nothing
of it (key package, relay lists, inbox subscription) reaches `relays` or
the defaults. A join that fails goes back to `relays`. Ignored once in a
mesh. `join()` alone switches to the code's relays only when it is called,
after the device has already published at start.

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
| `invite(target)` | `Invited` | Add a device (npub or `noscat:` URI). The device must be running or waiting in `join`. Once this returns the device is a member. `Invited { welcome_accepted }`: whether a relay also took its invitation (the Welcome). When `false`, say "added, invitation not delivered yet": the Welcome is resent in the background (wrapped afresh each time) while a client runs for this directory, until the device shows up or a week passes, and `Member::state` is `Pending` meanwhile. A relay accepting it is not proof of delivery either, so it is resent (more slowly) until the device is seen. A used key package (one an earlier Add consumed) is refused; with nothing else to use, the error says the device must publish a fresh one (`noscat join`). (New in 0.7.0; was `()`.) |
| `join(inviter, timeout)` | `()` | Wait for the inviter's invitation and join. The scanned QR (the inviter) is the trust anchor: invitations from anyone else are ignored. Pass the scanned code whole: when it names relays (`?relay=`, a private mesh's), the join goes through them alone, logged in (NIP-42). |
| `mesh_relays()` / `is_private()` | `Vec<String>` / `bool` | The mesh's relays; whether it is private. |
| `set_mesh_relays(relays)` | `()` | Replace the mesh's relays (1 to 16 `wss://` URLs). Every member moves to the new list. |
| `mesh_stun()` / `set_mesh_stun(servers)` | `Vec<String>` / `()` | The mesh's STUN servers (`ip:port`, no hostnames, at most 8; empty removes them). Each device uses them from its next start; config `stun_servers` overrides them. Without any, a shared mesh uses public STUN servers and a private mesh none. The FFI has `meshStun()` and `setMeshStun(servers)` (both blocking). |
| `set_private(bool)` | `()` | Make the mesh private (every device uses only the mesh's relays, logs in to them with NIP-42, leaves its own and the public ones) or shared again. Noscat logs in to no other relay. |
| `pairing_uri()` | `String` | What the pairing QR shows: `noscat:<npub>`, plus `?relay=` for each of a private mesh's relays. |
| `remove(target)` | `()` | Remove a member. Every member is an admin and may do this. |
| `leave(timeout)` | `()` | Leave; waits for another member to commit it. With none in time it forgets the mesh locally anyway: the request stays on the relays and the next member to come online completes it. The last member just forgets the mesh. When there is nothing to leave, the error message contains "this device is not in a mesh". |
| `members()` | `Vec<Member>` | `npub, name, admin, this_device, online, last_seen_secs, reachable, control, connected, state`. `state` (`MemberState`, new in 0.7.0; `Default` is `Active`): `Active` once it has sent anything (or it was a member before this device joined), `Pending` while a member added since this device joined has not been heard from (show it as joining), `NeverJoined` once a week has passed without a word from it (it most likely never got its invitation: offer to remove it and invite it again). Persistent: unlike presence, it survives restarts. `control`: it offers a terminal (see Terminal). `online`: its advert arrived over the relays recently, which says nothing about whether data can reach it. `connected`: data can flow to it now (a direct link or a live connection, possibly relayed). While `up` or `expose` runs, the client keeps a connection to every online member (dialing every 30 s), so online but not connected means seen but unreachable. `reachable`: its latest advert says it is reachable from the internet. A `Roster` event follows every connection change. Sorted for display: this device first, then by name (case-insensitive), then unnamed devices, ties by npub; presence never reorders it, and `Roster` events carry the same order. |
| `member_age_secs(npub)` / `member_online(npub)` | `Option<u64>` / `bool` | Presence from adverts (sent every 2 minutes, fresh for 10). |
| `join_requests()` | `Vec<JoinRequest>` | `npub, name, age_secs`: devices that asked to join in the last 15 minutes and are not members yet, oldest first. Read from the relays, so a process started after the request (a CLI next to a service) sees it too; the `JoinRequest` event is the live signal. Invite one with `invite(npub)`. Not in the FFI (the apps use the event). |
| `network_changed()` | `()` | Re-check paths after a network switch. Apps call it when the platform reports a new default network (Wi-Fi to cellular and back): without it, paths through the old address take minutes to time out. |
| `events()` | `Option<Receiver<Event>>` | Take the receiver once; pump it forever. |

Access (who may do what to this device; new in 0.6):

Incoming streams fall in three groups: `AccessGroup::Send` (files, chat,
clipboard), `Services` (forwards) and `Control` (terminal, from 0.6). Each
member gets an `AccessRule` per group: `Allow`, `Deny` or `Ask` (Control
only). Defaults: send and services allow, control asks. Rules are saved in
the state directory (`access.json`, sealed under a storage key) and never
leave the device. A refused opener gets `ClientError::Stream` with "not
permitted" (chat: `ChatFailed`, files: `TransferFailed`).

| Method | Returns | Contract |
|---|---|---|
| `access_defaults()` | `AccessRules` | `send, services, control`: the rules for members without their own. |
| `access_of(device)` | `AccessRules` | The rules that apply to `device` (its own, else the defaults). |
| `access_devices()` | `Vec<(String, Vec<(AccessGroup, AccessRule)>)>` | Members with rules of their own (npub) and those rules. |
| `set_access(device?, group, rule?)` | `()` | Set a member's rule (`None` device: the default; `None` rule: back to the default). `Ask` outside Control is an error. Saved at once. |
| `reset_access(device)` | `()` | Drop a member's own rules. |
| `set_access_prompts(on)` | `()` | An app is here to answer prompts. Off (the default: a headless host), a group set to ask refuses at once and logs `NoOneToAsk`. |
| `answer_access(id, answer)` | `()` | Answer an `AccessRequest`: `AccessAnswer::Once`, `Always` (also saves an allow rule) or `Deny`. Errors once it no longer waits. |
| `answer_waiting(device, group, allow)` | `bool` | Answer a member's waiting request without its id (the CLI's `allow`/`deny`); whether one waited. |
| `allow_once(device, group)` | `()` | Allow the waiting request, or else the member's next one (until the client stops). |
| `access_requests()` | `Vec<AccessRequest>` | `id, peer, group, age_secs, outcome`: waiting requests, then the last 50 refused or asked ones, newest first. `AccessOutcome`: `Waiting, Allowed, Denied, TimedOut, NoOneToAsk`. A refusal repeating within a minute is one entry. |

In the FFI as `accessDefaults()`, `accessOf(npub)`, `accessCustom()` (npubs only), `setAccess`, `resetAccess`, `setAccessPrompts`, `answerAccess`, `accessRequests()`.

Terminal (new in 0.6; hosting on computers only, viewing everywhere):

| Method | Returns | Contract |
|---|---|---|
| `open_terminal(target, cols, rows, term)` | `MeshStream` | Blocks until the member's shell started; `TerminalWaiting` fires while it asks its user (it gives up after 60 s). The stream carries `TermFrame`s (`encode()`, `TermFrame::read(&mut stream)`): write `Input(bytes)` and `Resize { cols, rows }`, read `Output(bytes)` until `Exit(status)`. Dropping it ends the session. Refused: `ClientError::Stream` with "not permitted" or "does not offer this". |
| `terminal_sessions()` | `Vec<TerminalSession>` | `id, peer, secs`: sessions members have open here. |
| `end_terminal(id)` | `bool` | Kill a session's shell; the viewer gets `Exit(-1)`. Whether it was open. |
| `start_terminal(target, cols, rows, term)` | `TerminalHandle` | For apps: `open_terminal` with the stream run by the client. `id()`, `peer()`, `write(bytes)`, `resize(cols, rows)`, `close()` (also on drop). Output arrives as `TerminalOutput { session, data }`, the end as `TerminalExited { session, code, error }` (the last event of the session). |
| `state_dir()` | `&Path` | The state directory. Hosted sessions are logged in its `terminal.log` (who, when, how long, exit status). |

A device offers a terminal (`Member::control`, the advert's `control`
tag) when it can host one and some member could get in: an allow rule,
or ask with an app attached (`set_access_prompts(true)`). Show the
terminal action only for members with `control`.

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
| `send_chat(target, text)` / `send_clipboard(target, text)` | `()` | Delivery is `ChatDelivered` or `ChatFailed`. Text up to 64 KiB. A send that fails on an existing connection is tried once more on a fresh one. Never resent automatically after `ChatFailed` (the member may have it already); apps offer a manual retry. |
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
| `ChatFailed` | `peer, error` | Keep the optimistic copy, mark undelivered, and offer a manual retry (Noscat already tried a fresh connection once). |
| `Clipboard` | `peer, text` | Put `text` on the system clipboard. |
| `Stopped` | `what, error` | A background operation stopped. |
| `MeshJoined` | `name` | This device is in a mesh now (created or joined). |
| `Roster` | `members` | The member list changed; `members` is in `members()` order. |
| `MemberSeen` | `peer, name` | A member's advert arrived. |
| `MeshChangeUndone` | | A membership change of ours lost a race with another member's; retry it. |
| `MeshLeft` | | Removed, or left. |
| `JoinRequest` | `peer, name` | A device that scanned this device's QR (or otherwise knows its npub) asks to be invited: prompt, then `invite(peer)`. Only while in a mesh; at most once per request. |
| `AccessRequest` | `id, peer, group` | A member asks for a group set to ask: prompt (allow once, always allow, deny), then `answer_access(id, ..)` within `ACCESS_ASK_TIMEOUT` (60 s). Only after `set_access_prompts(true)`. |
| `AccessResolved` | `id, peer, group, outcome` | An asked request ended (answered here, by the CLI, or timed out): close its prompt. |
| `TerminalWaiting` | `peer` | Viewer: `open_terminal` waits while `peer` asks its user. |
| `TerminalOpened` | `id, peer` | Host: a member's session started here. Keep a banner up while any is open, with a way to end it. |
| `TerminalClosed` | `id, peer, secs, error` | Host: a session ended (`error`: the shell could not start). |
| `TerminalOutput` | `session, data` | Viewer: bytes from a `start_terminal` session, in order. |
| `TerminalExited` | `session, code, error` | Viewer: the session ended: `code` the exit status (`-1` ended by the host), or `None` with `error` when the connection broke. |

Inbound streams are always handled by the client, after its access check.

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
| `start_debug_log(path, filter)` | Append noscat's logs at `filter` (a RUST_LOG filter, such as `noscat_core=debug`) to the file at `path`, for diagnosing; phones have no stderr. The first call wins. Call before the client starts to log its start. |
| `generate_identity()` | New `Identity { npub, secret_hex }`. |
| `identity_from_secret(secret)` | Restore from hex or nsec. |
| `mesh_prepare(dir, owner?, relays?)` | This directory's npub, creating `identity.nsec` if missing. `owner` is unused (kept for call compatibility). |
| `mesh_join(dir, timeout_secs, owner_npub, relays?)` | Wait for an invitation from `owner_npub` (bare npub or `noscat:` URI) and join; the inviter is sent a join request. A URI naming relays starts the device with them as `join_relays`, so nothing reaches public relays. Returns the members. A timeout is the error "no invitation arrived in time". |
| `mesh_members(dir, relays?)` | The members. Presence (`online`, `last_seen_secs`) is only known while a client runs for `dir`. |
| `mesh_sync(dir, wait_secs, relays?)` | The members after catching up: immediate when a client runs for `dir`, else after running the device for `wait_secs`. |
| `mesh_create(dir, name, relays?)` | New mesh with this device as the only member. |
| `mesh_invite(dir, npub, relays?)` | Add a device; it must be running or in `mesh_join`. Returns `Boolean` (new in 0.7.0): whether a relay accepted its invitation; `false` = added, invitation not delivered yet (see `invite` above; resent while a client runs for `dir`). |
| `mesh_remove(dir, npub, relays?)` | Remove a member. |
| `mesh_leave(dir, timeout_secs, relays?)` | Leave; waits for another member to complete it (see `leave` above for the timeout case). Deleting `dir` afterwards, once no client runs on it, makes the next join a new device. |

### Records

- `ClientConfig { identity_secret?, relays?, mesh_dir?, device_name?, listen_port? }`. With `mesh_dir` and no `identity_secret`, the client uses the
  dir's `identity.nsec`; apps should do that rather than read the file,
  which is sealed under a storage key.
  `listen_port` None = any free port.
- `MeshMember { npub, name?, last_seen_secs?, online, admin, this_device, reachable, connected, control, state }` (see `members()`).
  Every device is an admin. `state` is the UniFFI enum `MemberState`
  (`Active`, `Pending`, `NeverJoined`), new in 0.7.0.
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

`npub()`, `meshName()`, `pairingUri()` (blocking: what the QR shows, with a private mesh's relays), `deviceName()`, `setDeviceName(name)` (blocking), `members()`, `invite(npub)`, `remove(npub)`,
`networkChanged()`, `forward(target, localPort)`, `listForwards()`,
`cancelForward(id)`, `expose(toHost, toPort)`, `servePort(port, enabled)`,
`sendFile(path, target)` (returns the transfer id), `cancelTransfer(path, target)`,
`receiveFile(outDir)`, `sendChat(target, text)`,
`sendClipboard(target, text)`, `up(outDir, bridgePort?)`.

New in 0.6: `meshStun()` and `setMeshStun(servers)` (blocking), the access calls above,
`terminalSessions()`, `endTerminal(id)`, and `openTerminal(target, cols,
rows)` (blocking until the member's shell started; `TerminalWaiting`
fires while it asks) returning a `Terminal` object: `id()`,
`write(ByteArray)`, `resize(cols, rows)`, `end()` (`close()` releases the object, which ends it too). `MeshMember` gains
`control` (it offers a terminal), and the access types are UniFFI enums
and records: `AccessGroup`, `AccessRule`, `AccessRules`, `AccessAnswer`,
`AccessOutcome`, `AccessRequest`, `TerminalSessionInfo`.

New in 0.7.0: `invite(npub)` returns `Boolean` (a relay accepted the
invitation; `false` = added, invitation not delivered yet, resent in the
background), and `MeshMember` gains `state: MemberState`.

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
to be invited: show a prompt, then `invite(peer)`). New in 0.6: `AccessRequest { id, peer, group }`,
`AccessResolved { id, peer, group, outcome }`, `TerminalWaiting { peer }`,
`TerminalOpened { id, peer }`, `TerminalClosed { id, peer, secs, error? }`,
`TerminalOutput { session, data: ByteArray }` and
`TerminalExited { session, code?, error? }`, as in Rust.

---

## Mesh behavior contracts (both surfaces)

- One device per state directory: `mesh-state.json` (group keys and
  membership, written 0600 and atomically) and `relay-sync.json` (where
  the relay subscription resumes). The identity lives wherever
  `IdentitySource` says; the CLI and apps keep `identity.nsec` next to
  the state.
- A mesh is a Marmot group (MLS). Noscat meshes interoperate with
  White Noise and other MDK clients: a White Noise account can be invited
  into a mesh and a Noscat device into a White Noise group. Only Noscat
  devices use the data plane.
- Every member is an admin. Two members changing membership within
  seconds of each other converge on one result; the loser sees
  `MeshChangeUndone` (ADR 0007).
- `join` accepts only an invitation from the named inviter.
- After joining, a device drops its key package's private keys and asks
  the relays to delete the published package (NIP-09); members refuse a
  key package an earlier Add consumed. Invitations are resent until the
  new member is seen (see `invite`).
- Adverts (name, presence) travel inside the group, so relays see neither.

## Versioning

- Crates ship in lockstep; the workspace version is the release version.
- Breaking changes to any `pub` item listed here are allowed between
  releases but MUST land in the same commit as this file's update, and
  the app repos get an adoption note on their tracking issue.
- `cargo semver-checks` runs in the release workflow as a mechanical
  backstop for signature changes.
