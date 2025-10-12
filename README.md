## Cross-compiling on macOS
See `tcpdump/README.md` for cross-compiling setup and build instructions. Following those steps builds the `tcpdump` binary for the `aarch64-unknown-linux-musl` target, producing a statically linked Linux ARM64 binary from macOS using musl.

## Create an Ubuntu VM
Install Multipass by following the official documentation for your operating system: https://documentation.ubuntu.com/multipass/latest/tutorial/

Then create a lightweight Ubuntu 24.04 VM and confirm it is running:

```
% multipass launch --name ubuntu-2404 --cpus 1 --memory 1G --disk 5G 24.04
% multipass ls
Name                    State             IPv4             Image
ubuntu-2404             Running           192.168.64.5     Ubuntu 24.04 LTS
```

- `--name ubuntu-2404`: Sets the VM instance name.
- `--cpus 1`: Allocates 1 virtual CPU.
- `--memory 1G`: Allocates 1 GB of RAM.
- `--disk 5G`: Allocates a 5 GB disk.
- `24.04`: Uses the Ubuntu 24.04 image.
- `multipass ls`: Lists running and stopped Multipass instances.

## Transfer the `tcpdump` Binary to the VM
Copy the built `tcpdump` binary into the VM user's home directory as `~/tcpdump`:

```
% multipass transfer target/aarch64-unknown-linux-musl/release/tcpdump ubuntu-2404:tcpdump
```

## Run `tcpdump` Inside the VM
```
% multipass exec ubuntu-2404 -- bash -c 'sudo RUST_LOG=info ./tcpdump'
Waiting for Ctrl-C...

or

% multipass shell ubuntu-2404
ubuntu@ubuntu-2404:~$ sudo RUST_LOG=info ./tcpdump
Waiting for Ctrl-C...

```

- `multipass exec ... 'sudo ./tcpdump'`: Runs a one-off command inside the VM as root.
- `multipass shell ...` followed by `sudo ./tcpdump`: Opens an interactive shell and runs it manually.
- `sudo`: Required to load eBPF programs and capture events.
- While running, the program prints "Waiting for Ctrl-C...". Press Ctrl-C to stop.

### Sample Output
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
[INFO  tcpdump] 0   0       0       swapper/0        2025-10-12T20:05:51.9577553+09:00  out  ESTABLISHED  1 192.168.64.5:41786     142.251.42.164:443
[INFO  tcpdump] 0   1317744 1317744 curl             2025-10-12T20:05:52.176226294+09:00 out  FIN_WAIT1    4 192.168.64.5:41786     142.251.42.164:443
[INFO  tcpdump] 0   0       0       swapper/0        2025-10-12T20:05:52.186390581+09:00 out  FIN_WAIT2    5 192.168.64.5:41786     142.251.42.164:443
[INFO  tcpdump] 0   0       0       swapper/0        2025-10-12T20:05:52.18644504+09:00 out  CLOSE        7 192.168.64.5:41786     142.251.42.164:443
```

- `CPU`: Logical CPU that emitted the perf event.
- `PID` / `TGID` / `COMM`: Process and thread identifiers plus the command name for the task that triggered the TCP state change.
- `TIME`: Local timestamp (RFC3339) reconstructed from monotonic time so it aligns with wall-clock time.
- `DIR`: Direction inferred from the SYN state and whether the ports look ephemeral (`out`, `in`, or `?`).
- `STATE` / `ID`: TCP state label and the numeric identifier defined by the kernel (for example `CLOSE_WAIT`, `LAST_ACK`).
- `SRC` / `DST`: Local and remote IPv4 socket addresses shown in `IP:port` form.
- `[WARN tcpdump] aya-log disabled`: Indicates that `AYA_LOGS` is not set; logging still works.
- Logs continue until you press Ctrl-C. Redirect the output to a file if you need to analyze it later.
