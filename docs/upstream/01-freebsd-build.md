<!-- Note to you: two small patches, one issue body. Patches are in
patches/0001-... and patches/0002-... . Everything below the line is the
text to send. -->

---

**Title:** Build fails on FreeBSD (and other non-Linux/macOS unixes): two small fixes

Hi! I'm embedding `nvpn-fips-core` / `nvpn-fips-endpoint` in a Rust app that
ships for Linux, macOS, Windows, Android and FreeBSD. 0.4.124 builds on all of
them except FreeBSD, where two things break. Both fixes are small; patches
attached.

### 1. `nvpn-mdns-sd`: `socket-pktinfo` 0.3 uses Linux-only `IP_PKTINFO`

```
error[E0425]: cannot find value `IP_PKTINFO` in crate `libc`
error[E0425]: cannot find type `in_pktinfo` in crate `libc`
```

`socket-pktinfo` 0.4 handles FreeBSD properly (it uses `IP_RECVDSTADDR`
there). Bumping the dependency is the whole fix:

```diff
 [dependencies.socket-pktinfo]
-version = "0.3.2"
+version = "0.4.2"
```

Verified on `nvpn-mdns-sd 0.19.2`:
- `cargo check` passes for `x86_64-unknown-freebsd`, `x86_64-unknown-linux-gnu`,
  `x86_64-pc-windows-gnu` and `aarch64-apple-darwin` (and fails on FreeBSD
  with 0.3.2, as a control).
- `cargo test` on Linux: all 87 tests pass with 0.4.2.

### 2. `nvpn-fips-core`: `underlay::bind_socket_to_interface` missing on other unixes

`transport::udp::underlay` is compiled only for android/ios/linux/macos, but
its callers (`socket_unix_raw.rs` and the STUN socket in
`discovery/nostr/runtime.rs`) are compiled for every unix, so FreeBSD fails
to resolve `crate::transport::udp::underlay`.

The patch compiles the module on `cfg(unix)` and adds a fallback for the
other unixes: no interface requested is `Ok(())`, a named interface returns
`io::ErrorKind::Unsupported`. Windows is untouched (no callers there).

```diff
-#[cfg(any(
-    target_os = "android",
-    target_os = "ios",
-    target_os = "linux",
-    target_os = "macos"
-))]
+#[cfg(unix)]
 pub(crate) mod underlay;
```

plus the fallback function in `underlay.rs` (see patch, 26 lines).

Verified with both patches applied to 0.4.124 (through `[patch.crates-io]`):
`cargo check` passes for `x86_64-unknown-freebsd`, `x86_64-pc-windows-gnu`,
`x86_64-unknown-linux-musl`, `aarch64-apple-darwin` and
`aarch64-linux-android`. Earlier, a full FreeBSD 14.5 cross-build and link
of an app using `FipsEndpoint` succeeded with the same `underlay` change plus
a compile-only stand-in for the pktinfo fix; I haven't redone the full link
with exactly these two patches.

I didn't find a portable BSD equivalent of `SO_BINDTODEVICE` /
`IP_BOUND_IF`, so `Unsupported` seemed more honest than a partial
implementation. Happy to adjust if you'd prefer something else.

Thanks for the crates, they've been great to build on.
