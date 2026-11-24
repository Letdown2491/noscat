{
  description = "noscat: like netcat, but over your own device mesh: npub-addressed, end-to-end encrypted, no root, no accounts";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      packages = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        rec {
          noscat = pkgs.rustPlatform.buildRustPackage {
            pname = "noscat";
            version = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).workspace.package.version;
            src = ./.;
            # cargoLock fetches the vendored dependencies from Cargo.lock
            # directly; no manual hash pinning to forget on a version bump.
            cargoLock.lockFile = ./Cargo.lock;
            # Only the CLI: the workspace also holds the FFI library and its
            # uniffi-bindgen helper, which do not belong in a profile.
            cargoBuildFlags = [ "-p" "noscat" ];
            # The FIPS data plane links libdbus on Linux (its Bluetooth
            # transport, via bluer) and generates bindings with bindgen
            # (libclang), until those become optional upstream.
            nativeBuildInputs = [ pkgs.pkg-config pkgs.rustPlatform.bindgenHook ];
            buildInputs = pkgs.lib.optionals pkgs.stdenv.isLinux [ pkgs.dbus ];
            # doCheck = false: the tests run real relays and FIPS over
            # loopback UDP, which the build sandbox does not reliably allow;
            # CI runs them instead.
            doCheck = false;
            meta = with pkgs.lib; {
              description = "Like netcat, but over your own device mesh: npub-addressed, end-to-end encrypted, no root, no accounts";
              homepage = "https://github.com/Letdown2491/noscat";
              license = licenses.mit;
              mainProgram = "noscat";
              platforms = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
            };
          };
          default = noscat;
        });

      apps = forAllSystems (system: {
        default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/noscat";
        };
      });
    };
}
