# Setup
```bash
# I'll set up a Linux cross-linker using Zig and cargo-zigbuild, then build the crate for x86_64-unknown-linux-gnu from the project directory.
brew install zig
# Install cargo-zigbuild
cargo install cargo-zigbuild --locked
# Install Rust nightly toolchain
rustup toolchain install nightly && rustup component add rust-src --toolchain nightly && rustup target add x86_64-unknown-linux-gnu --toolchain nightly

```

# Build

```bash
cd ebpf-based-tcpdump
cargo +nightly zigbuild -Z build-std=std,panic_abort --target x86_64-unknown-linux-gnu
```

