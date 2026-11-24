# API.md - the app-facing API contract

The public surface the client apps consume: `noscat-client` (Rust, embedded
directly by noscat-desktop) and `noscat-ffi` (UniFFI, consumed by
noscat-android and later mobile platforms).

> **Current as of 0.4.2.** If your `Cargo.lock` pins a newer version than
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
| `noscat-client` | noscat-desktop (direct dep) | `Client`, `Event`, config, identity sources |
| `noscat-ffi` | noscat-android (UniFFI bridge) | `NoscatClient`, `Event`, mesh helpers, identity helpers |
| `noscat-core` | private (client + ffi + cli) | Noise tunnels, MLS mesh, relay clients, the wire spec |

---

## noscat-client (Rust)

### Identity and config

```rust
pub enum IdentitySource {
    Ephemeral,       // fresh keypair per process
    Secret(String),  // hex secret or nsec1...
    File(PathBuf),   // created 0600 on first use if missing
}

pub struct ClientConfig {
    pub identity: IdentitySource,          // default: Ephemeral
    pub relays: Option<Vec<String>>,       // None = default public relay set
    pub listen: Option<SocketAddr>,        // default: 0.0.0.0:41641
    pub mesh_dir: Option<PathBuf>,         // mesh-scoped tunnels (see Mesh)
    pub device_name: Option<String>,       // published in the advert
    pub advert_ttl_secs: u64,              // default: core ADVERT_TTL_SECS
    pub max_incoming_bytes: Option<u64>,   // None = wire ceiling (~5.4 TiB)
}
```

`ClientConfig::default()` is intentionally conservative; UIs set `identity`,
`mesh_dir`, and `device_name`.

### Client

`Client::start(config) -> Result<Client, ClientError>`. Cloning shares one
node; dropping the last reference stops the runtime and every background
operation it owns.

Connection and lifecycle:

| Method | Returns | Contract |
|---|---|---|
| `npub()` | `&str` | This node's address. Cheap. |
| `connect(target)` | `TunnelStream` | Dial a peer npub (or `noscat:<npub>?...` URI). |
| `listen()` | `SocketAddr` | Serve mode: publish the advert, accept inbound tunnels. Emits `Listening` + `Incoming`. |
| `up(out_dir, bridge_to)` | `SocketAddr` | listen + auto-receive files into `out_dir` + optional TCP bridge for non-file streams. |
| `pipe_stdio(target)` | `()` | Dial and bridge the tunnel to stdio (netcat mode). |
| `serve_stdio()` | `()` | listen and bridge the FIRST inbound tunnel to stdio. |
| `expose(to)` | `SocketAddr` | Local TCP listener; every accept dials `to` over a tunnel. |

Transfers:

| Method | Returns | Contract |
|---|---|---|
| `send_file(path, target)` | `()` | Async; progress/completion arrives as events. Whole-file sha256 in the header. |
| `cancel_transfer(target, path)` | `bool` | Receiver keeps its resumable partial; a resend of the same file resumes. |
| `receive_file(out_dir)` | `()` | Accept inbound transfers into `out_dir` (mesh-scoped auth). |
| `send_chat(target, text)` | `()` | Fire and forget; delivery is `ChatDelivered`/`ChatFailed`. |
| `send_clipboard(target, text)` | `()` | Same delivery semantics as chat. |

Forwards:

| Method | Returns | Contract |
|---|---|---|
| `forward(target, local)` | `u64` | id; every local accept dials `target` over a tunnel. |
| `list_forwards()` | `Vec<ForwardInfo>` | |
| `cancel_forward(id)` | `bool` | Emits `ForwardStopped`. |

Mesh (read paths the UI uses at runtime):

| Method | Returns | Contract |
|---|---|---|
| `member_age_secs(npub_hex)` | `Option<u64>` | Seconds since the member's freshest advert; `None` = unknown/offline. |
| `member_online(npub_hex)` | `bool` | Advert fresher than the TTL. |
| `events()` | `Option<Receiver<Event>>` | Take the event receiver once, pump it forever. |

Mesh-scoped behavior (when `mesh_dir` is set):

- Only mesh members can connect or be dialed: tunnels are sealed with the
  group's epoch PSK.
- The PSK is RE-READ FROM DISK on every dial/accept: membership changes
  made by other processes (a `mesh invite` while `up` runs) pick up on the
  next tunnel without a restart.
- Mesh join/sync/resend are NOT on `Client`: they live in `Device`
  (core, used via the CLI) or the `noscat-ffi` `mesh_*` functions.

### Event (exhaustive; UIs must match every variant)

| Variant | Fields | Meaning |
|---|---|---|
| `Listening` | `npub, addr` | Serve side is up; the pairing QR banner belongs here. |
| `Incoming` | `peer, addr, stream` | Inbound tunnel accepted (listener mode). The stream carries one sniffed prefix byte. |
| `TunnelUp` | `peer, addr` | A dialed or accepted tunnel is ready. |
| `TunnelClosed` | `peer, error` | Tunnel ended; `error` set when not a clean close. |
| `TransferDone` | `peer, path` | Whole file verified (sha256) and renamed into place. On send, `path` is the source. |
| `TransferPartial` | `peer, path` | Receive ended WITHOUT a verified whole file: `.noscat-part` is a resume seed only. |
| `TransferProgress` | `peer, path, sent, total` | Sends only, one event per percent. |
| `TransferFailed` | `peer, path, error` | |
| `TransferCancelled` | `peer, path` | Cancelled by this side. |
| `ForwardStopped` | `id, error` | Forward ended (cancel or failure); drop it from the UI list. |
| `ChatMessage` | `peer, text` | One-shot chat arrival. |
| `ChatDelivered` | `peer` | The peer echoed FIN with the text in hand. |
| `ChatFailed` | `peer, error` | Keep the optimistic copy, mark undelivered. |
| `Clipboard` | `peer, text` | Put `text` on the system clipboard. |
| `Stopped` | `what, error` | A background op (listener, expose, forward) stopped. |

Delivery contracts:

- Events arrive on a client-owned thread. UIs must hop to their main
  thread before touching UI state (the Android app's rule 5).
- The event channel is bounded; the pump must drain it continuously or
  the node stalls.
- Nothing in the client prints to stderr: if a UI needs narration it
  renders its own from events. Logging goes through `tracing` at warn
  level by default.

### Errors

`ClientError`: `Identity(String) | Mesh(String) | Io(io::Error) | Tunnel(TunnelError)`.
`TunnelError` variants are core-internal; match on the display string, do
not exhaustively match core errors.

---

## noscat-ffi (Kotlin via UniFFI, Swift later)

### Functions

| Function | Contract |
|---|---|
| `generate_identity()` | New `Identity` record. |
| `identity_from_secret(secret)` | Restore from hex or nsec. |
| `mesh_members(dir, relays?)` | Roster of a mesh device directory, names + `last_seen_secs` resolved from live adverts (None = offline). |
| `mesh_prepare(dir, owner?, relays?)` | Publish this device's MLS key package as a join request, addressed to `owner_npub` when given. Returns this device's npub. |
| `mesh_join(dir, timeout_secs, owner_npub, relays?)` | Wait for the owner's gift-wrapped invitation and join. Accepts a bare npub or a `noscat:<npub>?...` URI. The deadline is enforced INSIDE core (a caller timeout would leak the relay session); a too-short wait surfaces as a clean timeout error, not a hang. |
| `mesh_sync(dir, for_secs, relays?)` | Merge the owner's epoch commits: backfill of stored commits first, then a live listen. |
| `mesh_resend(dir, to_npub?, relays?)` | OWNER ONLY: replay the journaled commit chain so a stranded member catches up. Returns how many gift wraps were sent. Non-owners get a clear NotOwner error. |

### NoscatClient

`NoscatClient(config, listener)`; mirror of the Rust `Client` above:

`npub()`, `forward(target, localPort)`, `listForwards()`,
`cancelForward(id)`, `expose(toHost, toPort)`, `sendFile(path, target)`,
`cancelTransfer(path, target)`, `receiveFile(outDir)`,
`sendChat(target, text)`, `sendClipboard(target, text)`,
`up(outDir, bridgePort?)`.

Threading contract (the Android app's rules 5 and 6, restated because they
are the ones apps keep violating):

- `EventListener.on_event` fires on a background thread: hop to main
  before touching UI.
- Never call any `NoscatClient` method or `mesh_*` function on the main
  thread: even cheap getters can block behind relay work and ANR.

### Event (UniFFI enum, exhaustive when-match required)

Same set as the Rust `Event` with `path: String` instead of `PathBuf`,
`Listening { npub, port }` instead of a SocketAddr, and no `Incoming`
(raw inbound streams are consumed by the node dispatcher, never surfaced).

---

## Mesh behavior contracts (both surfaces)

- One identity per device dir (`identity.nsec`); the mesh group state
  (`mls.sqlite3`, `mesh.json`) is per-dir. A device directory is enrolled
  exactly once.
- `mesh_join` refuses invitations from anyone but `owner_npub`, and
  refuses groups whose policy does not name that owner: the scanned QR is
  the trust anchor.
- Only the owner commits. Members enforce this at commit-merge time
  (signed credential vs. the policy extension).
- GroupContext extensions are set at creation and propagate unchanged:
  wire-format changes to the policy are NOT backward compatible by
  design. Groups created before 0.4.1 are unsupported; recreate the mesh
  on the owner and re-invite. (`docs/nip-noscat.md` is the wire contract.)
- Join-request journaling (`join-requests/`, `mesh requests/accept/
  decline` in the CLI) is CLI-only today; the FFI/client surface for it
  is a fast-follow when an app needs it.
- Device-state diagnostics: `noscat_core::mesh::store_report(dir)`
  returns a `StoreReport` (row counts for the OpenMLS tables, sidecar
  and journal presence) with `looks_wiped()` / `packages_without_keys()`
  detecting the wiped-store signature of issue #14 - a device holding
  no usable keys cannot decrypt Welcomes and needs the remove + re-join
  recovery. The CLI exposes it as `noscat mesh doctor`.

## Versioning

- Crates ship in lockstep; the workspace version is the release version.
- Breaking changes to any `pub` item listed here are allowed between
  releases but MUST land in the same commit as this file's update, and
  the app repos get an adoption note on their tracking issue.
- `cargo semver-checks` runs in the release workflow as a mechanical
  backstop for signature changes.
