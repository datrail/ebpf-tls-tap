# eBPF TLS Tap

eBPF TLS Tap is DatRail's low-level Linux TLS observation component. It builds
`bpf/sslsniff`, which attaches uprobes to OpenSSL, GnuTLS, and NSS and prints
decrypted TLS traffic for inspection and downstream parsing, and
`bpf/listensnoop`, which reports every TCP, UDP or ICMP-echo socket that
starts accepting inbound traffic.

## Quick start

On a Linux host with a BTF-enabled kernel:

```bash
git clone --recursive https://github.com/datrail/ebpf-tls-tap.git
cd ebpf-tls-tap
sudo apt-get install clang llvm gcc libelf-dev zlib1g-dev libssl-dev make git
make build-bpf
sudo ./bpf/sslsniff -c curl
```

Use `-p <pid>` to restrict capture to one process or `--hexdump` to print raw
payload bytes. Run `sudo ./bpf/sslsniff --help` for all options.

## Listening sockets

An agent that opens a local port is offering a service nobody declared — a
covert channel no TLS call ever reveals. `listensnoop` reports each TCP, UDP
or ICMP-echo socket that starts accepting inbound traffic, as it appears:

```bash
sudo ./bpf/listensnoop            # or -p <pid> / -u <uid>
```

```json
{"timestamp_ns":76326320956582,"kind":"listen","pid":4211,"tid":4211,"host_pid":2957315,"uid":1000,"comm":"python3","protocol":"tcp","family":"ipv4","addr":"127.0.0.1","port":38135}
```

One JSON object per line, one line per socket:

- `"kind":"listen"`: a TCP socket entered LISTEN (`inet_csk_listen_start`).
  A repeated `listen()` that only resizes the backlog is not reported again.
- `"kind":"bind"`: a UDP socket bound a local port (`inet_bind`,
  `inet6_bind`). UDP has no `listen()`, so this is the only signal a UDP server
  gives. An unprivileged ICMP "ping" socket (`SOCK_DGRAM`, not raw) is
  reported the same way, with `protocol` `icmp`/`icmpv6` and its echo
  identifier as `port`: it receives every echo reply carrying that
  identifier. TCP binds are not reported; a TCP socket that never listens is
  a client.
- `"kind":"autobind"`: an unbound UDP or ping socket's first `sendto()` bound
  it (`inet_send_prepare`). Unconnected, it now receives from anyone. This also
  covers a bind made with `IP_BIND_ADDRESS_NO_PORT`, which gets its port here.
  A `connect()` is not reported, since a connected socket only hears its peer.
- `"kind":"lost","count":N`: up to N events were missed. The count includes
  events the ring buffer had no room for, and calls the kernel skipped
  because the same program was already running on that CPU (its
  `recursion_misses`). The second kind can be caused deliberately by an
  unprivileged process. The count is an upper bound, since a skipped call
  might not have produced an event. It appears within a poll interval, even
  if no event follows it, so a flood cannot hide one `listen()` silently.
  Treat a gap as "unknown", not "no change". Skips are counted host-wide,
  whatever `-p`/`-u` say, so any process can inflate the count. That is
  noisy, but it is not silent.
- Address and port are read after the kernel assigned them, so a bind to port
  0, or a `listen()` with no `bind()`, reports the port actually chosen.
- Failed calls produce nothing.
- `pid`, `tid` and `-p` use the numbering of `listensnoop`'s own PID namespace.
  On the host, a containerised agent gets its host PID. Inside a container you
  get the PIDs you see there, and a process outside the container's namespace
  has `pid` 0 and only `host_pid`. `uid` is the kernel's (initial user
  namespace) view.
- Not covered:
  - sockets already listening when it starts (read `/proc/net/{tcp,udp}{,6}`
    for those);
  - SCTP;
  - raw and packet sockets;
  - IPv6 UDP binds when IPv6 is a module that is not loaded (it warns on
    stderr).

It needs BTF and fentry/fexit: Linux 5.17 or newer on x86-64, 6.0 on arm64.
All hooks are fentry/fexit, so concurrent calls cannot exhaust return-probe
slots the way kretprobes can. Events go to their own 1 MiB BPF ring buffer,
separate from sslsniff's.

Measured on a 7.3 kernel:
- about 0.9 µs added per `listen()`/`bind()` call;
- about 28 ns (3%) added per `sendmsg()` on any inet socket, because the
  autobind hook sits on the send path;
- 80,000 events in a tight loop with none lost;
- 300 binds under 400 threads contending on `bind()`, all reported.

`tests/listensnoop_test.py` runs in CI and checks the exact event set against
real sockets: TCP, UDP and ICMP, IPv4 and IPv6, a nested PID namespace,
native-thread contention, CPU oversubscription and a stalled reader.

## Architecture

```mermaid
flowchart LR
  process[Target process] -->|TLS library calls| bpf[eBPF uprobes]
  bpf --> events[Perf-event buffer]
  events --> sslsniff[Userspace sslsniff]
  sslsniff -->|Multiline plaintext or hex| output[Terminal or parser]
  process -->|listen / bind / first sendto| kfn[eBPF fentry/fexit on kernel socket functions]
  kfn --> ring[Ring buffer + drop counter]
  ring --> listensnoop[Userspace listensnoop]
  listensnoop -->|JSON lines| output
```

sslsniff's kernel program observes TLS-library entry and return points; its
loader reads events and prints a column header followed by multiline plaintext
or hexadecimal payload blocks. The repository pins the libbpf, bpftool, and
kernel type-header sources needed for reproducible builds.

## Security

These programs require elevated BPF privileges. sslsniff exposes plaintext
that TLS normally protects; listensnoop reads no payload, only socket
addresses, process names and IDs. Restrict capture to the intended process,
protect stdout and downstream logs, and never run either on a host or workload
you are not authorized to observe. Read [SECURITY.md](SECURITY.md) and report vulnerabilities privately
through GitHub Security Advisories.

## Development

```bash
git submodule update --init --recursive
make build-bpf
sudo python3 tests/listensnoop_test.py   # listensnoop end to end (needs cc, python3)
```

The build and probe checks require the Linux C/eBPF toolchain; see
[`bpf/Makefile`](bpf/Makefile) and the GitHub Actions workflow for exact CI
dependencies.

## Related projects

- [RailMon](https://github.com/datrail/railmon) provides DatRail's supported
  structured capture and export path through AgentSight.
- [RailDash](https://github.com/datrail/raildash) presents structured captures.

## License

DatRail userspace source, build glue, and documentation are Apache-2.0. The
kernel eBPF programs (`bpf/*.bpf.c`) are GPL-2.0-only, and vendored upstream trees retain their
own per-file licenses. See [LICENSE](LICENSE), [LICENSES](LICENSES/), and
[NOTICE](NOTICE).
