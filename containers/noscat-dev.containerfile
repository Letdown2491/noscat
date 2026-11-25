# noscat dev image: the host is atomic (bootc) and has no toolchain, so
# cargo runs in this container. Same pattern as bitchat-rs and riddim:
#   Build:  podman build -t localhost/noscat-dev -f containers/noscat-dev.containerfile containers/
#   Check:  podman run --rm -v "$PWD:/work:Z" -w /work localhost/noscat-dev cargo check
#   Test:   podman run --rm -v "$PWD:/work:Z" -w /work localhost/noscat-dev cargo test
#
# Fedora 43 base keeps the built binaries' glibc in step with the host
# (f43 carries 2.42-era glibc). gcc is needed for the C glue in ring and
# rust-secp256k1 (nostr's crypto stack). dbus-devel and clang-devel are for
# nvpn-fips-core on glibc, which always pulls in bluer (libdbus) and
# rustables (bindgen/libclang); drop them once the optional-features patch
# (docs/upstream/02-optional-native-deps.md) is released upstream.

FROM fedora:43

# Rust toolchain baked into the image: CARGO_HOME/RUSTUP_HOME live in image
# layers (not volumes), so the image is self-contained; only target/ is
# shared with the host checkout.
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:/usr/bin:/bin
RUN curl -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile minimal

RUN dnf -y install gcc pkgconf-pkg-config git dbus-devel clang-devel \
  && dnf clean all
