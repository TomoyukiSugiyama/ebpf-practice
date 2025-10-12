## Cross-compiling on macOS
See `tcpdump/README.md` for cross-compiling setup and build instructions. Following those steps, you can build the `tcpdump` binary for the `aarch64-unknown-linux-musl` target.

This produces a statically linked Linux ARM64 binary from macOS using musl.

## Create a VM for Ubuntu
It is necessary to install Multipass. Please follow the official documentation for detailed installation instructions, making sure to select the appropriate procedure for your operating system. Administrator privileges may be required for installation.
https://documentation.ubuntu.com/multipass/latest/tutorial/

Use the following commands to create a lightweight Ubuntu 24.04 VM and verify it is running:

```
% multipass launch --name ubuntu-2404 --cpus 1 --memory 1G --disk 5G 24.04
% multipass ls
Name                    State             IPv4             Image
ubuntu-2404             Running           192.168.64.5     Ubuntu 24.04 LTS
```

- **--name ubuntu-2404**: Sets the VM instance name.
- **--cpus 1**: Allocates 1 virtual CPU.
- **--memory 1G**: Allocates 1 GB of RAM.
- **--disk 5G**: Allocates a 5 GB disk.
- **24.04**: Uses the Ubuntu 24.04 image.
- **multipass ls**: Lists running and stopped Multipass instances.

## Transfer the tcpdump binary to the VM 

Copies the built `tcpdump` binary from your host into the VM user's home directory as `~/tcpdump`.

```
% multipass transfer target/aarch64-unknown-linux-musl/release/tcpdump ubuntu-2404:tcpdump
```

## Start the tcpdump binary in a virtual machine
```
% multipass exec ubuntu-2404 -- bash -c 'sudo RUST_LOG=info ./tcpdump'
Waiting for Ctrl-C...

or

% multipass shell ubuntu-2404
ubuntu@ubuntu-2404:~$ sudo RUST_LOG=info ./tcpdump
Waiting for Ctrl-C...

```

- **multipass exec ... 'sudo ./tcpdump'**: Runs a one-off command inside the VM as root.
- **multipass shell ...** then `sudo ./tcpdump`: Opens an interactive shell and runs it manually.
- **sudo**: Required to load eBPF programs and capture packets.
- While running, you'll see "Waiting for Ctrl-C...". Press Ctrl-C to stop.

### Sample output
```
ubuntu@ubuntu-2404:~$ sudo RUST_LOG=info ./tcpdump
[WARN  tcpdump] aya-log disabled: AYA_LOGS not found
Waiting for Ctrl-C...
[INFO  tcpdump] CPU PID     TGID    COMM             TIME                                DIR  STATE       ID SRC                    DST
[INFO  tcpdump] 0   0       0       swapper/0        2025-10-12T20:05:22.974164523+09:00 in   CLOSE_WAIT   8 192.168.64.5:22        192.168.64.1:62883
[INFO  tcpdump] 0   1310352 1310352 sshd             2025-10-12T20:05:22.985865406+09:00 in   LAST_ACK     9 192.168.64.5:22        192.168.64.1:62883
[INFO  tcpdump] 0   1       1       systemd          2025-10-12T20:05:22.986245575+09:00 in   CLOSE        7 192.168.64.5:22        192.168.64.1:62883
[INFO  tcpdump] 0   0       0       swapper/0        2025-10-12T20:05:26.895601264+09:00 in   ESTABLISHED  1 192.168.64.5:22        192.168.64.1:63493
[INFO  tcpdump] 0   1317532 1317532 curl             2025-10-12T20:05:37.576407805+09:00 out  SYN_SENT     2 127.0.0.1:0            127.0.0.1:80
[INFO  tcpdump] 0   1317532 1317532 curl             2025-10-12T20:05:37.576476556+09:00 out  CLOSE        7 127.0.0.1:56408        127.0.0.1:80
[INFO  tcpdump] 0   1317744 1317744 curl             2025-10-12T20:05:51.950932039+09:00 out  SYN_SENT     2 192.168.64.5:0         142.251.42.164:443
[INFO  tcpdump] 0   0       0       swapper/0        2025-10-12T20:05:51.9577553+09:00   out  ESTABLISHED  1 192.168.64.5:41786     142.251.42.164:443
[INFO  tcpdump] 0   1317744 1317744 curl             2025-10-12T20:05:52.176226294+09:00 out  FIN_WAIT1    4 192.168.64.5:41786     142.251.42.164:443
[INFO  tcpdump] 0   0       0       swapper/0        2025-10-12T20:05:52.186390581+09:00 out  FIN_WAIT2    5 192.168.64.5:41786     142.251.42.164:443
[INFO  tcpdump] 0   0       0       swapper/0        2025-10-12T20:05:52.18644504+09:00  out  CLOSE        7 192.168.64.5:41786     142.251.42.164:443
```

- `CPU`: Logical CPU that emitted the perf event.
- `PID` / `TGID` / `COMM`: Process/thread identifiers and command name for the task that triggered the TCP state change.
- `TIME`: Local timestamp (RFC3339) reconstructed from monotonic time, so it aligns with wall-clock time.
- `DIR`: Traffic direction heuristic (`out`, `in`, `?`). SYN 送信やエフェメラル/ウェルノウンポートから推定しています。
- `STATE` / `ID`: TCP state labelと、カーネル定義の数値 ID。`CLOSE_WAIT`, `LAST_ACK` などの遷移がそのまま表示されます。
- `SRC` / `DST`: ローカル/リモートの IPv4 アドレスとポートをソケット形式で表示します。
- `[WARN tcpdump] aya-log disabled`: `AYA_LOGS` 環境変数が未設定の場合の警告です。機能に問題はありません。
- ログは Ctrl-C を押すまで継続して流れます。終了後にファイルへリダイレクトして解析することも可能です。
