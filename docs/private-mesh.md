# Set up a private mesh

This guide takes you from nothing to a Noscat mesh that runs entirely on
infrastructure you control: your own relay, your own STUN server, and your
devices. No company, no account, and no third-party server ever learns
which devices are in your mesh or where they are.

It takes about 30 to 45 minutes. You will copy commands into a terminal on
a small server, then join your computers and phone. No programming needed.

## What you end up with

```
                 your server (a small VPS)
        ┌──────────────────────────────────────────┐
        │  Caddy          HTTPS for the relay       │
        │  noscat-relay   members-only relay, STUN  │
        │  Noscat         a mesh member everyone    │
        │                 can reach                 │
        └──────────────────────────────────────────┘
             ▲                ▲                ▲
             │   end-to-end encrypted, device to device
             │                │                │
        your laptop      your desktop      your phone
```

- **The relay** (noscat-relay) passes the mesh's control messages between
  devices: who is a member, invitations, "I'm online here" notes. Every one
  is encrypted, and it serves only your mesh's devices.
- **The server's Noscat device** is a member like any other, with one
  extra job: everyone can reach it from the internet, so devices behind
  home routers and mobile networks connect through it when they cannot
  connect directly.
- **STUN** (built into the relay) tells your devices their public address,
  so they can connect directly where possible, without asking Google or
  anyone else.

### What "private, decentralized, trustless" means here

- **Private.** Membership, invitations and presence go only through your
  relay. Files, chat, forwards and terminals go device to device,
  end-to-end encrypted. Your devices never contact public Nostr relays or
  public STUN servers.
- **Decentralized.** There is no coordinator and no owner. Every member
  can invite and remove devices, and every member checks the group's
  state for itself (it is an MLS group, the IETF standard for group
  encryption). The server is just one member.
- **Trustless.** Each device makes its own key; there is no account to
  take over and no password to leak. The relay stores only encrypted
  messages it cannot read. When the server passes traffic between two of
  your devices, it cannot read that either: the encryption is between the
  two devices.

What this does not hide, so you know where the edges are:

- Your hosting provider sees the server's traffic: which IP addresses
  talk to it, when, and how much. Not what is said.
- Your relay's domain name is public: anyone can see it exists (HTTPS
  certificates are published in public logs), and anyone can look it up.
  Only your devices can use it.
- The server is a full member. Anyone who takes over the server can do
  what any member can: invite a device, see who is in the mesh, use
  whatever your other devices allow it. Keep it updated and use SSH keys.
- The domain brings in a registrar, a DNS provider and a certificate
  authority. None of them can read or forge your mesh's messages, but
  whoever controls the domain could redirect it and see which devices
  log in, and when. Why it is needed for now, and when that ends, is
  under "Without a domain" below.
- Installing downloads from GitHub once (Noscat, the relay and the apps).
  After that, running the mesh needs no outside site at all.

## What you need

- **A server** with a public IPv4 address: any small VPS (1 CPU, 1 GB of
  RAM is plenty) running Debian 12 or 13, or Ubuntu 24.04. You need SSH
  access and `sudo`.
- **A domain name** (or a subdomain of one you own) that you can point at
  the server, for example `relay.example.com`.
- **Your devices**: Linux, macOS or Windows computers, and Android phones.

Throughout this guide, replace:

| Placeholder | With |
|---|---|
| `relay.example.com` | your relay's domain name |
| `203.0.113.10` | your server's public IPv4 address |

Every command in steps 1 to 5 runs **on the server**, over SSH, as your
normal user (not root). `sudo` is used only where needed.

## Step 1: Point your domain at the server, and open its ports

1. At your domain registrar or DNS provider, add an **A record**:
   `relay.example.com` → `203.0.113.10`. It can take a few minutes to
   apply. Check it from any computer:

   ```bash
   ping -c 1 relay.example.com     # should show 203.0.113.10
   ```

2. Open these ports on the server. If your provider has a firewall in its
   web dashboard, open them there too.

   | Port | For |
   |---|---|
   | TCP 80 and 443 | HTTPS for the relay (Caddy, which gets the certificate) |
   | UDP 41641 | Noscat: your devices connect to the server here |
   | UDP 3478 | STUN: your devices learn their public address here |

   With `ufw` (Ubuntu's firewall; on Debian, `sudo apt install ufw`
   first):

   ```bash
   sudo ufw allow OpenSSH
   sudo ufw allow 80,443/tcp
   sudo ufw allow 41641/udp
   sudo ufw allow 3478/udp
   sudo ufw enable
   ```

## Step 2: Install Noscat on the server

```bash
curl -fsSL https://raw.githubusercontent.com/Letdown2491/noscat/main/packaging/install.sh | sh
```

This puts `noscat` in `~/.local/bin`. Check it works (log out and back in
first if `noscat` is not found):

```bash
noscat --version
```

Give the server a name your devices will show (optional; it is the
hostname otherwise):

```bash
noscat name server
```

## Step 3: Install the relay

Download the relay (a single file) and its two configuration files.
This is for x86_64 servers; on ARM, use `noscat-relay-linux-arm64` in the
first `curl`:

```bash
mkdir -p ~/noscat-relay && cd ~/noscat-relay
curl -fsSL -o noscat-relay https://github.com/Letdown2491/noscat-relay/releases/latest/download/noscat-relay-linux-amd64
chmod +x noscat-relay
curl -fsSLO https://raw.githubusercontent.com/Letdown2491/noscat-relay/main/noscat-relay.service
curl -fsSL -o .env https://raw.githubusercontent.com/Letdown2491/noscat-relay/main/.env.example
```

(Prefer to build it yourself? The relay's README shows how, with Go.)

Open `.env` in an editor (`nano .env`) and set these three lines (the
other settings can stay as they are):

```bash
RELAY_URL="wss://relay.example.com"
MEMBERS_COMMAND="$HOME/.local/bin/noscat mesh members"
STUN_ADDR=":3478"
```

- `RELAY_URL` must be exactly your domain with `wss://` in front: devices
  log in to the relay by name, and a mismatch refuses every login.
- `MEMBERS_COMMAND` is how the relay learns who may use it: it asks the
  server's Noscat device for the mesh's members, every minute.
- `STUN_ADDR` turns on the relay's STUN server.

Save (in nano: Ctrl+O, Enter, Ctrl+X). Now run the relay as a service
that starts at boot:

```bash
mkdir -p ~/.config/systemd/user
cp noscat-relay.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now noscat-relay
sudo loginctl enable-linger "$USER"     # keep your services running when you log out
```

Check it started:

```bash
journalctl --user -u noscat-relay -n 20
```

You should see `Relay listening on 127.0.0.1:3340 for wss://relay.example.com`
and `STUN on udp [::]:3478`. Lines saying `members: source listed nobody`
are expected for now: there is no mesh yet.

## Step 4: Put HTTPS in front of the relay

Caddy gets a free certificate for your domain and renews it by itself.

```bash
sudo apt install caddy
```

Replace the contents of `/etc/caddy/Caddyfile` with these three lines
(`sudo nano /etc/caddy/Caddyfile`):

```caddyfile
relay.example.com {
    reverse_proxy localhost:3340
}
```

Then reload Caddy and check the relay answers over HTTPS:

```bash
sudo systemctl reload caddy
curl -s -H 'Accept: application/nostr+json' https://relay.example.com
```

The `curl` prints a short JSON description of the relay (its name,
"noscat relay"). If it fails, wait a minute (the certificate is being
issued) and check that ports 80 and 443 are open and the A record is
right.

## Step 5: Create the mesh on the server

Start the server's Noscat device as a service. It uses only your relay
from the start, and tells the mesh it is reachable at its public address:

```bash
noscat --relay wss://relay.example.com --reachable 203.0.113.10:41641 service install
noscat service status
```

Now create the mesh (call it whatever you like; `home` here), make it
private, and give it your STUN server:

```bash
noscat mesh create home
noscat mesh private
noscat mesh stun add 203.0.113.10:3478
```

Check:

```bash
noscat mesh relays
```

It should say the mesh is **private** and list only
`wss://relay.example.com`. Within a minute the relay's log shows
`members: 1 (was 0)`: the server is in.

## Step 6: Join your devices

Every new device joins the same way: it reads the server's **pairing
code**, asks to join, and you approve it on a member.

On the server, show the pairing code:

```bash
noscat mesh qr
```

It prints a QR code and a line like
`noscat:npub1...?relay=wss%3A%2F%2Frelay.example.com`. That `?relay=` part
matters: it tells a new device to use your relay and nothing else, so not
even its first message reaches a public relay. Always use the whole code.

### A phone (Android)

1. Install Noscat for Android (the APK from its
   [releases](https://github.com/Letdown2491/noscat-android/releases))
   and open it.
2. Tap **Scan pairing code** and scan the QR in your SSH terminal (make
   the terminal window big enough to show it whole). Or copy the
   `noscat:` line to the phone and paste it.
3. The phone waits for approval. Approve it on the server (below).

### A desktop computer (the app)

1. Install Noscat for desktop (from its
   [releases](https://github.com/Letdown2491/noscat-desktop/releases))
   and open it.
2. Paste the whole `noscat:` line into the join screen and press
   **Request to join**.
3. Approve it on the server (below).

### A computer with the command line

Install Noscat ([`INSTALL.md`](../INSTALL.md) has every platform), then:

```bash
noscat mesh join 'noscat:npub1...?relay=wss%3A%2F%2Frelay.example.com'
```

Keep the single quotes: the code contains characters your shell would
otherwise change. Then approve it on the server (below). To keep the
device running in the background afterwards:

```bash
noscat service install
```

It needs no `--relay`: a device in a private mesh uses the mesh's relays
by itself.

### Approving on the server

On the server, while the new device waits:

```bash
noscat mesh requests
```

It lists the devices that asked to join, each with its name and npub,
and asks `y/n` for each. **Check the npub** against the one the new
device shows on its screen before answering `y`: the name is the
device's own claim, the npub is its identity.

Once one app device is in, you can approve the rest from it instead:
requests show up on its **Devices** tab with **Approve** and
**Decline**. Any member can approve, and any member's pairing code
works for joining.

## Step 7: Check it works

On the server:

```bash
noscat mesh members
```

Every device should be listed as **online** and **connected**. In the
apps, the ring around the Noscat logo turns green.

Try it: send a chat message or a file from your phone to your laptop.
It goes device to device (or through your server, encrypted, when the
two cannot reach each other directly).

## Day to day

- **Adding a device**: step 6 again, with any member's pairing code (in
  the apps: **Invite a device**).
- **Removing a lost or sold device**: on the server (or any member with
  the command line), `noscat mesh remove <its npub>`; `noscat mesh
  members` lists the npubs. Its key no longer opens anything in the mesh,
  and the relay refuses it at once. (The apps cannot remove other devices
  yet; a phone or computer leaving on its own uses **Forget mesh** in its
  Settings.)
- **Terminals and access**: each device decides what the others may do
  to it (send files and messages, use its forwarded services, open a
  terminal). The server has no app to ask you, so it refuses terminals
  until you allow a device: `noscat allow laptop control`. See the
  README's "Who may do what".
- **Updating**: on the server, run the install line from step 2 again
  and `noscat service install` with the same options as in step 5; for
  the relay, run the first three lines of step 3 again, then
  `systemctl --user restart noscat-relay`. The two can restart in either
  order. The apps update like any app.
- **Backups**: the server's identity and mesh state are in
  `~/.local/share/noscat`. If the server is lost, set up a new one and
  join it to the mesh as a new device from any of your other devices;
  then remove the old server's npub. Your other devices keep their keys
  and their place in the mesh.

## If something is not working

| What you see | Likely cause and fix |
|---|---|
| A device stays "online" but never "connected" | UDP 41641 is blocked on the server (step 1, including the provider's firewall), or the address in `--reachable` is wrong. |
| Nothing ever connects (the apps stay amber), though `curl` works | `RELAY_URL` in `.env` does not match the domain exactly (`wss://`, no trailing slash), so every login is refused. Fix it and `systemctl --user restart noscat-relay`. |
| `curl https://relay.example.com` fails | The A record is not there yet, or TCP 80/443 is closed (Caddy needs both to get a certificate). `sudo journalctl -u caddy -n 50` says which. |
| A joining device waits forever | The request went to a member nobody is approving: run `noscat mesh requests` on the device whose code you used. Or the code was cut short: use the whole `noscat:` line. |
| Devices take a long time to connect directly | UDP 3478 is closed, so STUN does not answer: devices still connect, through the server. Open the port and restart the apps. |

Logs:

```bash
journalctl --user -u noscat -f           # the server's Noscat device
journalctl --user -u noscat-relay -f     # the relay
```

## Without a domain

The domain is there so the relay can have an HTTPS certificate, and for
now this guide needs it. A plain `ws://` relay on the server's IP address
works, but we no longer suggest it: the connection to the relay is not
encrypted. Messages stay end-to-end encrypted and signed, so nobody on the
way can read or forge them, but anyone between your devices and the
server (a café's Wi-Fi, an ISP) can see which device keys log in, when,
and how much they send, which is the metadata this setup is meant to
hide. Someone who can also change that traffic can reuse a device's login
to the relay: they still cannot read or forge anything, but they can see
the mesh's traffic pass and post junk that slows it down.

Noscat 0.8.0 removes the need for the domain: devices reach the relay
through the mesh itself, encrypted end to end and checked against the
server's npub, so there is no domain, no DNS, no certificate, and the
relay no longer faces the internet at all. This guide will switch to that.

## Going further

- **Moving an existing mesh** off public relays onto your own: see
  noscat-relay's README, "Moving a mesh onto it".
- **How it works**: the README's Relays section, and the protocol in
  [`nip-noscat.md`](nip-noscat.md).
