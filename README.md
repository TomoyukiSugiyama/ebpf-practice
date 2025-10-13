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

### Interactive UI controls
- パケット一覧はカーソルで選択でき、画面上部に最新のパケットが流れます。
- `↑ / ↓`: 1行スクロール
- `PgUp / PgDn`: 10行スクロール
- `Home / End`: 先頭 / 末尾へジャンプ
- `q`, `Q`, `Esc`, または `Ctrl-C`: 終了
- 選択した行の詳細が画面中央に、対応する生バイト列が画面下部に表示されます。

### Sample Output
```
┌Packets────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│  Time         Source             Destination        Protocol   Length   Info                                                                                                                                                                      │
│  10:24:25.882 192.168.64.1       192.168.64.5       TCP        256      53767 -> 22 seq=419894405 ack=1611894371 flags=[ACK,PSH] len=190                                                                                                          │
│  10:24:27.888 192.168.64.1       192.168.64.5       TCP        256      53767 -> 22 seq=419895389 ack=1611895547 flags=[ACK,PSH] len=190                                                                                                          │
│  10:24:29.893 192.168.64.1       192.168.64.5       TCP        256      53767 -> 22 seq=419896373 ack=1611896723 flags=[ACK,PSH] len=190                                                                                                          │
│  10:24:31.899 192.168.64.1       192.168.64.5       TCP        256      53767 -> 22 seq=419897357 ack=1611897899 flags=[ACK,PSH] len=190                                                                                                          │
│  10:24:33.898 192.168.64.1       192.168.64.5       TCP        256      53767 -> 22 seq=419898341 ack=1611899075 flags=[ACK,PSH] len=190                                                                                                          │
│  10:24:35.909 192.168.64.1       192.168.64.5       TCP        256      53767 -> 22 seq=419899325 ack=1611900251 flags=[ACK,PSH] len=190                                                                                                          │
│  10:24:37.911 192.168.64.1       192.168.64.5       TCP        256      53767 -> 22 seq=419900309 ack=1611901427 flags=[ACK,PSH] len=190                                                                                                          │
│  10:24:39.922 192.168.64.1       192.168.64.5       TCP        256      53767 -> 22 seq=419901293 ack=1611902603 flags=[ACK,PSH] len=190                                                                                                          │
│  10:24:41.947 192.168.64.1       192.168.64.5       TCP        256      53767 -> 22 seq=419902277 ack=1611903779 flags=[ACK,PSH] len=190                                                                                                          │
│  10:24:43.924 192.168.64.1       192.168.64.5       TCP        256      53767 -> 22 seq=419903261 ack=1611904955 flags=[ACK,PSH] len=190                                                                                                          │
│  10:24:45.937 192.168.64.1       192.168.64.5       TCP        256      53767 -> 22 seq=419904245 ack=1611906131 flags=[ACK,PSH] len=190                                                                                                          │
│  10:24:47.940 192.168.64.1       192.168.64.5       TCP        256      53767 -> 22 seq=419905229 ack=1611907307 flags=[ACK,PSH] len=190                                                                                                          │
│  10:24:49.940 192.168.64.1       192.168.64.5       TCP        256      53767 -> 22 seq=419906213 ack=1611908483 flags=[ACK,PSH] len=190                                                                                                          │
│  10:24:51.962 192.168.64.1       192.168.64.5       TCP        256      53767 -> 22 seq=419907197 ack=1611909659 flags=[ACK,PSH] len=190                                                                                                          │
│  10:24:53.959 192.168.64.1       192.168.64.5       TCP        256      53767 -> 22 seq=419908181 ack=1611910835 flags=[ACK,PSH] len=190                                                                                                          │
│  10:24:55.973 192.168.64.1       192.168.64.5       TCP        256      53767 -> 22 seq=419909165 ack=1611912011 flags=[ACK,PSH] len=190                                                                                                          │
│  10:24:57.972 192.168.64.1       192.168.64.5       TCP        256      53767 -> 22 seq=419910149 ack=1611913187 flags=[ACK,PSH] len=190                                                                                                          │
│  10:24:59.975 192.168.64.1       192.168.64.5       TCP        256      53767 -> 22 seq=419911133 ack=1611914363 flags=[ACK,PSH] len=190                                                                                                          │
│  10:25:02.005 192.168.64.1       192.168.64.5       TCP        256      53767 -> 22 seq=419912117 ack=1611915539 flags=[ACK,PSH] len=190                                                                                                          │
│  10:25:03.990 192.168.64.1       192.168.64.5       TCP        256      53767 -> 22 seq=419913101 ack=1611916715 flags=[ACK,PSH] len=190                                                                                                          │
│  10:25:05.986 192.168.64.1       192.168.64.5       TCP        256      53767 -> 22 seq=419914085 ack=1611917891 flags=[ACK,PSH] len=190                                                                                                          │
│  10:25:08.000 192.168.64.1       192.168.64.5       TCP        256      53767 -> 22 seq=419915069 ack=1611919067 flags=[ACK,PSH] len=190                                                                                                          │
│  10:25:10.003 192.168.64.1       192.168.64.5       TCP        256      53767 -> 22 seq=419916053 ack=1611920243 flags=[ACK,PSH] len=190                                                                                                          │
│  10:25:12.017 192.168.64.1       192.168.64.5       TCP        256      53767 -> 22 seq=419917037 ack=1611921419 flags=[ACK,PSH] len=190                                                                                                          │
│▶ 10:25:14.011 192.168.64.1       192.168.64.5       TCP        256      53767 -> 22 seq=419918021 ack=1611922595 flags=[ACK,PSH] len=190                                                                                                          │
└───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
┌Details────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│Timestamp   10:25:14.011                                                                                                                                                                                                                           │
│Frame       256 bytes                                                                                                                                                                                                                              │
│Ethernet    be:d0:74:70:ec:64 -> 52:54:00:dd:5d:19 type=0x0800                                                                                                                                                                                     │
│IPv4        192.168.64.1 -> 192.168.64.5 TTL=64 TotalLen=696                                                                                                                                                                                       │
│TCP         53767 -> 22 Seq=419918021 Ack=1611922595 Window=2048 Header=32 Payload=190                                                                                                                                                             │
│Flags       ACK,PSH                                                                                                                                                                                                                                │
│                                                                                                                                                                                                                                                   │
│                                                                                                                                                                                                                                                   │
│                                                                                                                                                                                                                                                   │
│                                                                                                                                                                                                                                                   │
│                                                                                                                                                                                                                                                   │
│                                                                                                                                                                                                                                                   │
│                                                                                                                                                                                                                                                   │
│                                                                                                                                                                                                                                                   │
│                                                                                                                                                                                                                                                   │
│                                                                                                                                                                                                                                                   │
│                                                                                                                                                                                                                                                   │
│                                                                                                                                                                                                                                                   │
│                                                                                                                                                                                                                                                   │
└───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
┌Raw Bytes──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│0000  52 54 00 dd 5d 19 be d0  74 70 ec 64 08 00 45 02  RT..]...tp.d..E.                                                                                                                                                                           │
│0010  02 b8 00 00 00 00 40 06  76 e7 c0 a8 40 01 c0 a8  ......@.v...@...                                                                                                                                                                           │
│0020  40 05 d2 07 00 16 19 07  70 c5 60 13 fc a3 80 18  @.......p.`.....                                                                                                                                                                           │
│0030  08 00 05 cf 00 00 01 01  08 0a 45 6b 9d 2b 7a d3  ..........Ek.+z.                                                                                                                                                                           │
│0040  1c 3e 81 03 8f 3a 47 4b  85 66 d1 e3 02 f0 b3 77  .>...:GK.f.....w                                                                                                                                                                           │
│0050  2c da 07 33 5b 8d d5 6d  39 cd e0 23 c0 c1 b0 cd  ,..3[..m9..#....                                                                                                                                                                           │
│0060  56 aa 16 d4 be db c3 ea  5b 50 d4 ca 24 9d f3 49  V.......[P..$..I                                                                                                                                                                           │
│0070  bd 92 eb 5b b3 69 89 42  4b f0 e6 92 cd 74 72 50  ...[.i.BK....trP                                                                                                                                                                           │
│0080  00 d6 58 b0 f8 70 39 aa  c5 22 c2 d2 fa 59 e1 e8  ..X..p9.."...Y..                                                                                                                                                                           │
│0090  d7 df c6 e5 0b f2 c7 17  53 36 53 23 cd e6 00 33  ........S6S#...3                                                                                                                                                                           │
│00a0  53 96 99 7c 2a 35 43 32  79 a8 0f 9e 51 3c 87 72  S..|*5C2y...Q<.r                                                                                                                                                                           │
│00b0  97 0a de 3f 2d 87 42 fa  9b 9c cc 0f d7 1c aa a5  ...?-.B.........                                                                                                                                                                           │
│00c0  a4 3b 1a 1b 58 66 bf 94  6c a8 7f 12 6a c1 89 3f  .;..Xf..l...j..?                                                                                                                                                                           │
│00d0  41 41 66 9c 9f f1 c2 29  92 e5 87 ae d0 46 66 95  AAf....).....Ff.                                                                                                                                                                           │
│00e0  e6 7b 5c e0 f9 ed ca f9  c7 ab 76 eb 25 0c 94 f9  .{\.......v.%...                                                                                                                                                                           │
│00f0  33 41 7e 0b c1 61 43 11  77 f4 ff c1 5f d7 59 ff  3A~..aC.w..._.Y.                                                                                                                                                                           │
│                                                                                                                                                                                                                                                   │
│                                                                                                                                                                                                                                                   │
│                                                                                                                                                                                                                                                   │
└───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```
