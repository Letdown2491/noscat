<!-- Note to you: one patch, patches/0003-... . Backward compatible: both new
features are on by default. Text to send is below the line. -->

---

**Title:** Make `bluer` and `rustables` optional (default-on features)

On glibc Linux, `nvpn-fips-core` always pulls in `bluer` (needs libdbus via
`libdbus-sys`) and `rustables` (needs libclang via bindgen). Apps that embed
FIPS as a userspace endpoint (`without_system_tun()`, no BLE transport, no
gateway) can't opt out, so every build machine and CI image needs
`dbus-devel` and `clang-devel` just to compile code that is never used.

The existing structure makes this a small change:

- `bluer` is only reached through the `bluer_available` cfg that `build.rs`
  sets, so `build.rs` now also requires the new `bluez-ble` feature.
- `rustables` is only used inside `gateway/`, gated by one `cfg` in `lib.rs`,
  which now also requires the new `linux-gateway` feature.
- Both features are in `default`, so existing users see no change.
  Embedders use `default-features = false`.

```toml
[features]
default = ["bluez-ble", "linux-gateway"]
bluez-ble = ["dep:bluer"]
linux-gateway = ["dep:rustables"]
```

(`optional = true` on the two target-specific dependencies, a one-line
`build.rs` change, a one-line `lib.rs` change. 13 lines added, 3 removed.)

Verified on 0.4.124:
- glibc Linux with `default-features = false` in an image without libdbus or
  libclang: `cargo check` passes, and `cargo tree -i bluer` / `-i rustables`
  find nothing. With default features in the same image it still fails on
  `libdbus-sys`, as before.
- glibc Linux with the libraries installed: `cargo check --lib` passes with
  default features and with `--no-default-features`.
- `cargo test --lib` with default features: 2849 passed, 24 ignored, 1
  failed. The failure
  (`portable_send_preserves_datagram_boundaries_order_and_ready_batch_tail`,
  "loopback datagram did not become readable") fails identically on
  unpatched 0.4.124 in the same container (3 of 3 runs each), so it is
  environmental or pre-existing, not from this change.

Feature names are only a suggestion.
