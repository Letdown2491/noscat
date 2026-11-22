{
  description = "noscat: like netcat, but over a Nostr-native mesh - npub-addressed tunnels, no root, no accounts";

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
            # The rusqlite "bundled" feature (which compiles its own sqlite)
            # does not survive buildRustPackage's vendored build here - the
            # link step looks for the system -lsqlite3 - so provide nix's.
            buildInputs = [ pkgs.sqlite ];
            # doCheck = false: the workspace test suite (the loss test in
            # particular) needs minutes of real UDP traffic that blows past
            # sandbox build timeouts; the release CI runs it instead.
            doCheck = false;
            meta = with pkgs.lib; {
              description = "Like netcat, but over a Nostr-native mesh: npub-addressed tunnels, no root, no accounts";
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
