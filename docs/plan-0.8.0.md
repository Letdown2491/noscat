# noscat 0.8.0 plan: macOS

0.8.0 brings the desktop app and Bluetooth to macOS, after 0.7.0 brought
Bluetooth to Linux and Android (`docs/plan-0.7.0.md`). Moved here from
0.7.0 on 2026-11-25, when the roadmap was re-cut.

- [ ] noscat-desktop on macOS: tray, Keychain for the storage key, an
      app bundle, signing and notarization (needs an Apple developer
      account).
- [ ] Bluetooth on macOS through CoreBluetooth in noscat-core (shared by
      the CLI and the app). The app asks for Bluetooth permission once.
      The CLI gets it when run from a terminal that has the permission;
      a background service (`brew services`) cannot ask, so the docs
      point background use with Bluetooth at the desktop app.

## Release

- [ ] Docs in all three repos, CI green, and the lockstep 0.8.0 per
      `docs/releasing.md`.
