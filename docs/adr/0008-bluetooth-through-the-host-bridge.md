---
status: proposed
date: 2026-11-25
---

# Bluetooth through FIPS's host bridge, with BlueZ over pure-Rust D-Bus on Linux

FIPS has a Bluetooth LE transport (L2CAP channels) with two ways in: a built-in Linux backend on `bluer`, which reaches BlueZ through the C library libdbus and is compiled only for glibc, and a host bridge (`host-ble-transport`) that leaves the platform calls to the application. noscat uses the host bridge on every platform. On Linux it answers it with zbus (pure-Rust D-Bus) for advertising and scanning, and kernel L2CAP sockets for data, so the static musl builds have Bluetooth and every Linux package keeps working without new dependencies.

## Considered options

- **FIPS's built-in `bluer` backend**: no code of ours on Linux, but glibc only and needs libdbus at run time. Bluetooth would be missing from the static packages (deb, rpm, apk, pacman, tarballs) or those would have to become dynamic.
- **Ship separate glibc builds with Bluetooth**: keeps `bluer`, but doubles the Linux artifacts and leaves musl systems without Bluetooth.
- **Host bridge with zbus and kernel sockets (chosen)**: one static binary everywhere; the same bridge shape as Android and macOS. We own the Linux glue (advertising, the bootstrap record, scanning, sockets).

## Consequences

- noscat carries a Linux Bluetooth module; FIPS's Linux backend stays unused.
- A machine needs BlueZ running; advertising may need the user to be permitted (a group or polkit rule, per distro).
- If `bluer` can be left out of the build entirely, glibc builds may stop needing libdbus (to check in the spike).
- Windows stays out: it offers no LE L2CAP channels to apps.
