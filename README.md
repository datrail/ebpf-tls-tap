# ebpf-tls-tap

eBPF TLS plain-text capture. Builds `bpf/sslsniff`, which attaches uprobes to
OpenSSL / GnuTLS / NSS and prints decrypted SSL/TLS traffic.

## Build

```bash
sudo apt-get install clang llvm gcc libelf-dev zlib1g-dev libssl-dev make git
git submodule update --init --recursive
make build-bpf
```

## Usage

```bash
sudo ./bpf/sslsniff
sudo ./bpf/sslsniff -p 181
sudo ./bpf/sslsniff -c curl
sudo ./bpf/sslsniff --hexdump
```

## License

- `sslsniff` sources: LGPL-2.1 OR BSD-2-Clause (derived from BCC sslsniff)
- Repository glue and documentation: MIT; see [LICENSE](LICENSE)
