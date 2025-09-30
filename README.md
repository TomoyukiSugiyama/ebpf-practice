## Cross-compiling on macOS
See `tcpdump/README.md` for cross-compiling setup and build instructions. Following those steps, you can build the `tcpdump` binary for the `aarch64-unknown-linux-musl` target.

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
% multipass exec ubuntu-2404 -- bash -c 'sudo ./tcpdump'
Waiting for Ctrl-C...

or

% multipass shell ubuntu-2404
ubuntu@ubuntu-2404:~$ sudo ./tcpdump 
Waiting for Ctrl-C...

```
