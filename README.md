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

- Kernel eBPF program (`bpf/sslsniff.bpf.c`): GPL-2.0-only
- DatRail userspace source, build glue, and documentation: Apache-2.0
- Vendored libbpf and bpftool trees: their upstream per-file licences

See [LICENSE](LICENSE), [LICENSES](LICENSES/), and [NOTICE](NOTICE).
