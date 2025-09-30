## Cross-compiling on macOS
```
CC=aarch64-linux-musl-gcc cargo build --package tcpdump --release \
  --target=aarch64-unknown-linux-musl \
  --config=target.aarch64-unknown-linux-musl.linker=\"aarch64-linux-musl-gcc\"
```
