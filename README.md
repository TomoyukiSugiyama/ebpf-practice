## Cross-compiling on macOS
```
CC=aarch64-linux-musl-gcc cargo build --package tcpdump --release \
  --target=aarch64-unknown-linux-musl \
  --config=target.aarch64-unknown-linux-musl.linker=\"aarch64-linux-musl-gcc\"
```

## Create a VM for Ubuntu
It is necessary to install Multipass. Please follow the official documentation for detailed installation instructions, making sure to select the appropriate procedure for your operating system. Administrator privileges may be required for installation.
https://documentation.ubuntu.com/multipass/latest/tutorial/

```
multipass launch --name ubuntu-2404 --cpus 1 --memory 1G --disk 5G 24.04
multipass ls
```

## Transfer the tcpdump binary to the VM 
```
multipass transfer target/aarch64-unknown-linux-musl/release/tcpdump ubuntu-2404:tcpdump
```

## Start the tcpdump binary in a virtual machine
```
% multipass exec ubuntu-2404 -- bash -c 'sudo ./tcpdump'                    (git)-[main]
Waiting for Ctrl-C...

or

% multipass shell ubuntu-2404
ubuntu@ubuntu-2404:~$ sudo ./tcpdump 
Waiting for Ctrl-C...

```
