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
% multipass exec ubuntu-2404 -- bash -c 'sudo ./tcpdump'
Waiting for Ctrl-C...

or

% multipass shell ubuntu-2404
ubuntu@ubuntu-2404:~$ sudo ./tcpdump 
Waiting for Ctrl-C...

```

- **multipass exec ... 'sudo ./tcpdump'**: Runs a one-off command inside the VM as root.
- **multipass shell ...** then `sudo ./tcpdump`: Opens an interactive shell and runs it manually.
- **sudo**: Required to load eBPF programs and capture packets.
- While running, you'll see "Waiting for Ctrl-C...". Press Ctrl-C to stop.
