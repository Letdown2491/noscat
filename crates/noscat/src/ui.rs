//! Terminal output: event narration (`# ` lines on stderr), the pairing
//! QR, the member table and the chat prompt of `noscat up`.

use noscat_client::{Client, Event, Member};

use crate::clipboard;
use crate::control::Row;

/// The pairing QR (`noscat:<npub>`, or a full pairing URI as given) for
/// terminals, colors inverted so it scans on the usual dark background.
pub fn render_pairing_qr(target: &str) -> Option<String> {
    let uri = if target.starts_with("noscat:") { target.to_string() } else { format!("noscat:{target}") };
    let code = qrcode::QrCode::new(uri).ok()?;
    Some(
        code.render::<qrcode::render::unicode::Dense1x2>()
            .dark_color(qrcode::render::unicode::Dense1x2::Light)
            .light_color(qrcode::render::unicode::Dense1x2::Dark)
            .quiet_zone(true)
            .build(),
    )
}

pub fn short(npub: &str) -> String {
    if npub.len() > 16 { format!("{}…", &npub[..16]) } else { npub.to_string() }
}

/// A member's display label: its name, else its short npub.
pub fn label(members: &[Member], npub: &str) -> String {
    members
        .iter()
        .find(|m| m.npub == npub)
        .and_then(|m| m.name.clone())
        .unwrap_or_else(|| short(npub))
}

pub fn age(secs: u64) -> String {
    match secs {
        s if s < 60 => format!("{s}s"),
        s if s < 3600 => format!("{} min", s / 60),
        s if s < 86_400 => format!("{} h", s / 3600),
        s => format!("{} d", s / 86_400),
    }
}

pub fn print_members(mesh: Option<&str>, rows: &[Row]) {
    match mesh {
        Some(name) => println!("mesh {name:?}, {} member(s)", rows.len()),
        None => {
            println!("not in a mesh (create one with `noscat mesh create <name>` or join with `noscat mesh join <npub>`)");
            return;
        }
    }
    for r in rows {
        let presence = if r.this_device {
            "this device".to_string()
        } else {
            match (r.online, r.last_seen_secs) {
                (true, Some(s)) => format!("online, seen {} ago", age(s)),
                (false, Some(s)) => format!("offline, seen {} ago", age(s)),
                (_, None) => "not seen yet".to_string(),
            }
        };
        let reach = if r.reachable { ", reachable" } else { "" };
        // Only a running `up` keeps connections, so only say "connected"
        // when it is; its absence claims nothing.
        let conn = if r.connected { ", connected" } else { "" };
        println!("{}  {:<20} {presence}{conn}{reach}", r.npub, r.name.as_deref().unwrap_or("-"));
    }
    if let Some(note) = no_reachable_note(rows.iter().map(|r| (r.reachable, r.this_device || r.last_seen_secs.is_some()))) {
        println!("{note}");
    }
}

/// The warning for a mesh with no member reachable from the internet, once
/// another member has been heard from (before that it is unknown).
/// `members` yields (reachable, heard from) per member, this device
/// included as heard from.
pub fn no_reachable_note(members: impl Iterator<Item = (bool, bool)>) -> Option<&'static str> {
    let (mut any_reachable, mut heard) = (false, 0);
    for (reachable, seen) in members {
        any_reachable |= reachable;
        heard += usize::from(seen);
    }
    (!any_reachable && heard > 1).then_some(
        "note: no member is reachable from the internet, so members on different networks \
         cannot meet. Run one (a home server or VPS) with `noscat up --reachable`.",
    )
}

/// Narrate one event. `members` labels peers by name.
pub fn print_event(ev: &Event, members: &[Member]) {
    match ev {
        Event::Listening { npub, addr } => {
            eprintln!("# 🐈 up as {npub} on udp/{addr} (Ctrl-C to quit)");
        }
        Event::TunnelUp { peer } => eprintln!("# 🔗 connected to {}", label(members, peer)),
        Event::TunnelClosed { peer, error } => match error {
            Some(e) => eprintln!("# ⚠️  connection to {} failed: {e}", label(members, peer)),
            None => eprintln!("# 🔁 connection to {} closed", label(members, peer)),
        },
        Event::TransferStarted { .. } => {}
        Event::TransferDone { peer, path, .. } => eprintln!("# ✅ {} <-> {}", label(members, peer), path.display()),
        Event::TransferPartial { path, .. } => eprintln!(
            "# ⚠️  transfer ended incomplete: partial kept at {} (a resend of the same file resumes)",
            path.display()
        ),
        Event::TransferProgress { .. } => {}
        Event::TransferFailed { error, .. } => eprintln!("# ⚠️  transfer failed: {error}"),
        Event::TransferCancelled { path, .. } => eprintln!("# ✋ transfer cancelled: {}", path.display()),
        Event::ForwardStopped { id, error: Some(e) } => eprintln!("# ⚠️  forward {id} failed: {e}"),
        Event::ForwardStopped { id, error: None } => eprintln!("# ✋ forward {id} stopped"),
        Event::ChatMessage { peer, text } => {
            let who = label(members, peer);
            println!("# 💬 {who}: {text}");
        }
        Event::Clipboard { peer, text } => {
            let who = label(members, peer);
            match clipboard::set_system_clipboard(text) {
                Ok(()) => println!("# 📋 clipboard from {who}: copied {} bytes", text.len()),
                Err(e) => {
                    println!("# 📋 clipboard from {who}:");
                    println!("{text}");
                    eprintln!("# ⚠️  no clipboard tool worked ({e}); text above");
                }
            }
        }
        Event::ChatFailed { peer, error } => eprintln!("# ⚠️  message to {} not delivered: {error}", short(peer)),
        Event::ChatDelivered { peer } => eprintln!("# ✓ delivered to {}", label(members, peer)),
        Event::Stopped { what, error } => match error {
            Some(e) => eprintln!("# ⚠️  {what} stopped: {e}"),
            None => eprintln!("# {what} stopped"),
        },
        Event::MeshJoined { name } => eprintln!("# ✅ in mesh {name:?}"),
        Event::Roster { members } => eprintln!("# 👥 mesh now has {} member(s)", members.len()),
        Event::MemberSeen { .. } => {}
        Event::MeshChangeUndone => {
            eprintln!("# ⚠️  another member changed the mesh at the same moment and won; retry your change");
        }
        Event::MeshLeft => eprintln!("# 👋 this device is no longer in a mesh"),
        // The CLI answers no prompts (a headless host), so these arrive
        // only from an embedding app; narrate them anyway.
        Event::AccessRequest { peer, group, .. } => {
            eprintln!("# 🔐 {} asks for {}; `noscat allow` or `noscat deny` answers", label(members, peer), group.name());
        }
        Event::AccessResolved { peer, group, outcome, .. } => {
            eprintln!("# 🔐 {} {}: {outcome:?}", label(members, peer), group.name());
        }
        Event::JoinRequest { peer, name } => {
            let who = name.as_deref().unwrap_or("a device");
            eprintln!(
                "# 🙋 {who} ({peer}) asks to join; type `invite {peer}` to add it \
                 (or, from another terminal, `noscat mesh requests`)"
            );
        }
    }
}

/// Pick a member by name or npub prefix.
pub fn resolve(members: &[Member], q: &str) -> Result<String, String> {
    let q = q.trim();
    if let Ok(pk) = noscat_client::parse_pairing_target(q) {
        use nostr::nips::nip19::ToBech32 as _;
        return Ok(pk.to_bech32().unwrap_or_else(|_| pk.to_hex()));
    }
    let hits: Vec<&Member> = members
        .iter()
        .filter(|m| !m.this_device)
        .filter(|m| m.npub.starts_with(q) || m.name.as_deref().is_some_and(|n| n.eq_ignore_ascii_case(q)))
        .collect();
    match hits.as_slice() {
        [one] => Ok(one.npub.clone()),
        [] => Err(format!("no member matches {q:?}")),
        _ => Err(format!("{q:?} matches {} members; be more specific", hits.len())),
    }
}

fn list(members: &[Member]) {
    for m in members.iter().filter(|m| !m.this_device) {
        let state = if m.online { "online" } else { "offline" };
        eprintln!("#    {} {} ({state})", m.name.as_deref().unwrap_or("-"), short(&m.npub));
    }
}

/// Chat from the `up` terminal: `to` lists members, `to <name|prefix>`
/// picks one, other lines go to them; `clip` shares the clipboard;
/// `name <new name>` renames this device and saves it to `name_file`,
/// like `noscat name`.
pub fn spawn_chat_repl(client: Client, name_file: std::path::PathBuf) {
    std::thread::spawn(move || {
        let mut target: Option<String> = None;
        eprintln!("# 💬 chat: 'to' lists members, 'to <name>' picks one, then type; 'clip' shares your clipboard; 'invite <npub>' adds a device; 'name <new>' renames this device");
        for line in std::io::stdin().lines().map_while(Result::ok) {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let members = client.members();
            if line == "to" {
                list(&members);
                continue;
            }
            if let Some(name) = line.strip_prefix("name ") {
                let name = name.trim();
                if let Err(e) = std::fs::write(&name_file, format!("{name}\n")) {
                    eprintln!("# ⚠️  could not save the name ({e}); it lasts for this run");
                }
                client.set_device_name(name);
                eprintln!("# ✅ members now see this device as {name:?}");
                continue;
            }
            if let Some(who) = line.strip_prefix("invite ") {
                match client.invite(who.trim()) {
                    Ok(()) => eprintln!("# ✅ invited {}", who.trim()),
                    Err(e) => eprintln!("# ⚠️  invite failed: {e}"),
                }
                continue;
            }
            if let Some(q) = line.strip_prefix("to ") {
                match resolve(&members, q) {
                    Ok(npub) => {
                        eprintln!("# 💬 talking to {}", label(&members, &npub));
                        target = Some(npub);
                    }
                    Err(e) => {
                        eprintln!("# ⚠️  {e}");
                        list(&members);
                    }
                }
                continue;
            }
            let Some(npub) = &target else {
                eprintln!("# 💬 pick someone first: 'to' lists members");
                continue;
            };
            if line == "clip" {
                match clipboard::get_system_clipboard() {
                    Ok(text) if !text.is_empty() => client.send_clipboard(npub, &text),
                    Ok(_) => eprintln!("# 📋 the clipboard is empty"),
                    Err(e) => eprintln!("# ⚠️  could not read the clipboard ({e})"),
                }
            } else {
                client.send_chat(npub, line);
            }
        }
    });
}
