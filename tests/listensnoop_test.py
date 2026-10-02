#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 DatRail
"""Run the built bpf/listensnoop against real sockets and check what it reports.

Needs root and a BTF-enabled kernel, like the probe itself. A child process
opens sockets in every way that should, and should not, produce an event; the
test asserts the child gets exactly one event per listening socket, with the
port and address the kernel actually assigned, and nothing else. A second,
`-p`-filtered listensnoop must see the child and not a decoy process.

Three cases come from review findings on the first version, each of which
it failed:
- Hundreds of threads spinning on failing binds exhausted the kretprobes'
  return slots, so binds made alongside them went unreported (287 of 300).
  tests/bind_stress.c makes that load with native threads; every bind made
  under it must be reported.
- When the reader stalls and the buffer overflows, the gap must show up on
  stdout as a "lost" record, even if no event follows it.
- A process in a nested PID namespace (a container, seen from the host) must
  be reported with the PID listensnoop's namespace gives it, not 0.
- With 64 threads on two CPUs, preempted programs make the kernel skip calls
  (recursion_misses); every skipped call must be counted as lost, so events
  plus lost cover every successful bind and listen.
- An ICMP "ping" socket bound to an echo identifier hears every echo reply
  carrying it, and a bind with IP_BIND_ADDRESS_NO_PORT has no port until its
  first sendto(): one event each, with the identifier or real port.

Usage: sudo python3 tests/listensnoop_test.py [path/to/listensnoop]
"""
import json
import os
import select
import shutil
import subprocess
import sys
import tempfile
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BINARY = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "bpf", "listensnoop")

# Opens one socket per case and prints the expected events as JSON. Runs as
# its own process so its PID is distinct from the test's. Each socket stays
# open until the end so no port is reused within the run.
CHILD = r"""
import json, socket, sys
sys.stdin.readline()  # wait until the filtered listensnoop is attached
keep, expected = [], []

have_v6 = socket.has_ipv6
try:
    socket.socket(socket.AF_INET6, socket.SOCK_STREAM).close()
except OSError:
    have_v6 = False

def tcp(family, addr, bind=True):
    s = socket.socket(family, socket.SOCK_STREAM)
    if bind:
        s.bind((addr, 0))
    s.listen()
    s.listen(5)  # a second listen() only resizes the backlog: no new event
    keep.append(s)
    return s.getsockname()[1]

def udp(family, addr):
    s = socket.socket(family, socket.SOCK_DGRAM)
    s.bind((addr, 0))
    keep.append(s)
    return s.getsockname()[1]

expected.append(("listen", "tcp", "ipv4", "127.0.0.1", tcp(socket.AF_INET, "127.0.0.1")))
expected.append(("listen", "tcp", "ipv4", "0.0.0.0", tcp(socket.AF_INET, None, bind=False)))
port = udp(socket.AF_INET, "127.0.0.1")
expected.append(("bind", "udp", "ipv4", "127.0.0.1", port))
if have_v6:
    expected.append(("listen", "tcp", "ipv6", "::1", tcp(socket.AF_INET6, "::1")))
    expected.append(("bind", "udp", "ipv6", "::1", udp(socket.AF_INET6, "::1")))

# The first sendto() binds an unbound UDP socket, which then hears anyone.
a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
a.sendto(b"x", ("127.0.0.1", 9))
keep.append(a)
expected.append(("autobind", "udp", "ipv4", "0.0.0.0", a.getsockname()[1]))
a.sendto(b"x", ("127.0.0.1", 9))    # already bound: no second event

# IP_BIND_ADDRESS_NO_PORT: bind() reserves no port, so the report waits for
# the first sendto(), and comes once, with the real port.
n = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
n.setsockopt(socket.IPPROTO_IP, 24, 1)  # IP_BIND_ADDRESS_NO_PORT
n.bind(("127.0.0.1", 0))
n.sendto(b"x", ("127.0.0.1", 9))
keep.append(n)
expected.append(("autobind", "udp", "ipv4", "127.0.0.1", n.getsockname()[1]))

# An unprivileged ping socket, where net.ipv4.ping_group_range allows one.
try:
    p = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
except OSError:
    have_ping = False
else:
    have_ping = True
    p.bind(("127.0.0.1", 0))
    keep.append(p)
    expected.append(("bind", "icmp", "ipv4", "127.0.0.1", p.getsockname()[1]))

# Every port above was the kernel's choice. These two are asked for, and
# inside the ephemeral range (the probe's port came from it), which is where
# a guess from the number alone would call them ephemeral.
expected = [tuple(e) + (True,) for e in expected]
def asked_for_port():
    probe = socket.socket()          # TCP bind without listen: no event
    probe.bind(("127.0.0.1", 0))
    chosen = probe.getsockname()[1]
    probe.close()
    return chosen
def bind_asked(s):
    for _ in range(20):              # another process may take the port first
        try:
            s.bind(("127.0.0.1", asked_for_port()))
            return
        except OSError:
            pass
    raise SystemExit("no free port to ask for")
t = socket.socket()
bind_asked(t)
t.listen()
keep.append(t)
expected.append(("listen", "tcp", "ipv4", "127.0.0.1", t.getsockname()[1], False))
d = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
bind_asked(d)
keep.append(d)
expected.append(("bind", "udp", "ipv4", "127.0.0.1", d.getsockname()[1], False))

# A socket can release a port the kernel chose (connect(AF_UNSPEC)
# disconnects and unhashes it) and then bind one it asks for: that one is
# not ephemeral, whatever happened to the socket before.
import ctypes
libc = ctypes.CDLL(None, use_errno=True)
def disconnect(s):
    unspec = (ctypes.c_ubyte * 16)()  # sa_family 0: AF_UNSPEC
    if libc.connect(s.fileno(), unspec, 16) != 0:
        raise SystemExit(f"connect(AF_UNSPEC): errno {ctypes.get_errno()}")
r1 = socket.socket()
r1.bind(("127.0.0.1", 0))            # kernel-chosen, no event (no listen)
r1.connect(t.getsockname())
disconnect(r1)
bind_asked(r1)
r1.listen()
keep.append(r1)
expected.append(("listen", "tcp", "ipv4", "127.0.0.1", r1.getsockname()[1], False))
r2 = socket.socket()
r2.listen()                          # kernel-chosen listener: one event
expected.append(("listen", "tcp", "ipv4", "0.0.0.0", r2.getsockname()[1], True))
disconnect(r2)
bind_asked(r2)
r2.listen()
keep.append(r2)
expected.append(("listen", "tcp", "ipv4", "127.0.0.1", r2.getsockname()[1], False))

# MPTCP binds its subflow without going through inet_bind; the same reuse
# must read the same way. Its listeners report the subflow's protocol, tcp.
try:
    m = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 262)  # IPPROTO_MPTCP
except OSError:
    have_mptcp = False
else:
    have_mptcp = True
    m.listen()
    expected.append(("listen", "tcp", "ipv4", "0.0.0.0", m.getsockname()[1], True))
    disconnect(m)
    bind_asked(m)
    m.listen()
    keep.append(m)
    expected.append(("listen", "tcp", "ipv4", "127.0.0.1", m.getsockname()[1], False))
    m0 = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 262)
    m0.bind(("127.0.0.1", 0))
    m0.listen()
    keep.append(m0)
    expected.append(("listen", "tcp", "ipv4", "127.0.0.1", m0.getsockname()[1], True))
    if have_v6:                      # inet6_bind_sk, the other family's hook
        m6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM, 262)
        m6.bind(("::1", 0))
        m6.listen()
        keep.append(m6)
        expected.append(("listen", "tcp", "ipv6", "::1", m6.getsockname()[1], True))
        m6a = socket.socket(socket.AF_INET6, socket.SOCK_STREAM, 262)
        m6a.bind(("::1", 0))
        chosen = m6a.getsockname()[1]
        m6a.close()
        m6b = socket.socket(socket.AF_INET6, socket.SOCK_STREAM, 262)
        m6b.bind(("::1", chosen))      # asked for, though another socket's choice
        m6b.listen()
        keep.append(m6b)
        expected.append(("listen", "tcp", "ipv6", "::1", chosen, False))

# None of these accepts inbound traffic, so none may produce an event.
try:
    r = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    r.bind(("127.0.0.1", 0))        # raw: hears everything, bound or not
    keep.append(r)
except PermissionError:
    pass
c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
c.bind(("127.0.0.1", 0))            # TCP bind without listen: a client
keep.append(c)
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
u.connect(("127.0.0.1", 9))         # UDP autobind through connect
keep.append(u)
dup = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    dup.bind(("127.0.0.1", port))   # EADDRINUSE: a failed bind
    raise SystemExit("duplicate bind unexpectedly succeeded")
except OSError:
    pass
# SO_REUSEADDR lets two TCP sockets bind one port, but only the first may
# listen: the second listen() fails inside the hooked function itself.
first = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
first.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
first.bind(("127.0.0.1", 0))
second = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
second.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
second.bind(first.getsockname())
first.listen()
keep += [first, second]
expected.append(("listen", "tcp", "ipv4", "127.0.0.1", first.getsockname()[1], True))
try:
    second.listen()                 # EADDRINUSE: a failed listen
    raise SystemExit("second listen unexpectedly succeeded")
except OSError:
    pass

print(json.dumps({"expected": expected, "have_v6": have_v6,
                  "have_ping": have_ping, "have_mptcp": have_mptcp}), flush=True)
"""

# Run under `unshare --pid --fork`: listens, reports its port and the PID its
# own namespace gives it (1), then holds until told to exit.
NESTED = r"""
import os, socket, sys
s = socket.socket(); s.bind(("127.0.0.1", 0)); s.listen()
print(s.getsockname()[1], os.getpid(), flush=True)
sys.stdin.readline()
"""

DECOY = r"""
import socket, sys
sys.stdin.readline()
s = socket.socket(); s.bind(("127.0.0.1", 0)); s.listen()
print(s.getsockname()[1], flush=True)
"""


def start_snoop(*args, read=True):
    """Start listensnoop and wait until it is attached. With read=False its
    stdout is left unread until stop_snoop, so the pipe fills and it stalls."""
    proc = subprocess.Popen([BINARY, *args], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    proc.lines = []
    proc.reader = None
    if read:
        proc.reader = threading.Thread(
            target=lambda: proc.lines.extend(proc.stdout.read().decode().splitlines()))
        proc.reader.start()
    # Raw reads, not readline(): a buffered reader can swallow the "attached"
    # line along with an earlier warning, and select() never fires again.
    fd = proc.stderr.fileno()
    deadline = time.monotonic() + 20
    seen = b""
    while time.monotonic() < deadline and b"listensnoop: attached" not in seen:
        ready, _, _ = select.select([fd], [], [], 0.5)
        if ready:
            chunk = os.read(fd, 4096)
            if not chunk:
                break
            seen += chunk
        elif proc.poll() is not None:
            break
    if b"listensnoop: attached" in seen:
        sys.stderr.write(seen.decode(errors="replace"))
        return proc
    proc.kill()
    rest = proc.stderr.read()
    sys.exit(f"listensnoop {' '.join(args)} did not attach:\n"
             f"{(seen + rest).decode(errors='replace')}")


def stop_snoop(proc):
    time.sleep(1)  # let the ring buffer drain the last events
    proc.terminate()
    if proc.reader:
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            sys.exit("listensnoop did not exit within 10s of SIGTERM")
        err = proc.stderr.read()
        proc.reader.join(timeout=10)
        if proc.reader.is_alive():
            sys.exit("listensnoop's stdout did not close after it exited")
        lines = proc.lines
    else:
        out, err = proc.communicate(timeout=10)
        lines = out.decode().splitlines()
    if proc.returncode != 0:
        sys.exit(f"listensnoop exited {proc.returncode}:\n{err.decode()}")
    events = []
    for line in lines:
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            sys.exit(f"listensnoop printed a non-JSON line: {line!r}")
    return events


def key(e):
    return (e["kind"], e["protocol"], e["family"], e["addr"], e["port"], e["ephemeral"])


def main():
    failures = []

    def check(cond, msg):
        print(("ok:   " if cond else "FAIL: ") + msg)
        if not cond:
            failures.append(msg)

    everything = start_snoop()
    child = subprocess.Popen([sys.executable, "-c", CHILD],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    decoy = subprocess.Popen([sys.executable, "-c", DECOY],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    filtered = start_snoop("-p", str(child.pid))

    child_out, _ = child.communicate("go\n", timeout=120)
    decoy_out, _ = decoy.communicate("go\n", timeout=30)

    nested_pid = nested_port = None
    nested = None
    if shutil.which("unshare"):
        nested = subprocess.Popen(["unshare", "--pid", "--fork", sys.executable, "-c", NESTED],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        line = nested.stdout.readline().split()
        if len(line) != 2:  # unshare present but refused, as in some containers
            nested.kill()
            nested = None
    if nested:
        nested_port, inner_pid = map(int, line)
        # Its PID as this namespace sees it: the unshare process's only child.
        with open(f"/proc/{nested.pid}/task/{nested.pid}/children") as f:
            nested_pid = int(f.read().split()[0])
        nested.communicate("done\n", timeout=30)
        check(inner_pid == 1 and nested_pid != 1, "nested child runs in its own PID namespace")
    else:
        print("note: no usable unshare here; nested PID namespace case skipped")
    check(child.returncode == 0, "child opened every socket")
    check(decoy.returncode == 0, "decoy opened its socket")
    result = json.loads(child_out)
    expected = sorted(tuple(e) for e in result["expected"])
    decoy_port = int(decoy_out)
    if not result["have_v6"]:
        print("note: no IPv6 on this host; IPv6 cases skipped")
    if not result["have_ping"]:
        print("note: ping sockets not allowed here; ICMP case skipped")
    if not result["have_mptcp"]:
        print("note: MPTCP not available here; MPTCP case skipped")

    all_events = stop_snoop(everything)
    filtered_events = stop_snoop(filtered)

    lost = [e for e in all_events + filtered_events if e["kind"] == "lost"]
    check(not lost, f"no events lost ({lost})")
    all_events = [e for e in all_events if e["kind"] != "lost"]
    filtered_events = [e for e in filtered_events if e["kind"] != "lost"]

    mine = [e for e in all_events if e["pid"] == child.pid]
    check(sorted(key(e) for e in mine) == expected,
          f"exactly one event per listening socket, nothing for clients or "
          f"failed binds/listens\n      missing    "
          f"{sorted(set(expected) - set(key(e) for e in mine))}\n      unexpected "
          f"{sorted(set(key(e) for e in mine) - set(expected))}")
    check(all(e["comm"] == "python3" or e["comm"].startswith("python")
              for e in mine), "comm names the child")
    check(all(e["uid"] == os.getuid() for e in mine), "uid is the child's")
    check(any(e["pid"] == decoy.pid and e["port"] == decoy_port for e in all_events),
          "the unfiltered run also sees the decoy")

    if nested_pid is not None:
        hits = [e for e in all_events if e["port"] == nested_port and e["kind"] == "listen"]
        check(len(hits) == 1 and hits[0]["pid"] == nested_pid,
              f"nested-namespace listener reported with this namespace's PID "
              f"{nested_pid} ({hits})")

    check(all(e["pid"] == child.pid for e in filtered_events),
          "-p reports only that PID")
    check(sorted(key(e) for e in filtered_events) == expected,
          "-p still reports every event of that PID")

    stress = os.path.join(tempfile.mkdtemp(), "bind_stress")
    subprocess.run(["cc", "-O2", "-pthread", "-o", stress,
                    os.path.join(ROOT, "tests", "bind_stress.c")], check=True)

    snoop = start_snoop()
    load = subprocess.run([stress, "contend", "400", "300"], capture_output=True,
                          text=True, check=True, timeout=60)
    first, *rest = load.stdout.splitlines()
    isolated = first == "isolated 1"
    ports = {int(p) for p in rest}
    events = stop_snoop(snoop)
    seen = {e["port"] for e in events if e["kind"] == "bind" and e["comm"] == "bind_stress"}
    missing = len(ports - seen)
    # bind_stress keeps its binds on a CPU the spinners don't use, so none
    # can be skipped and none may be missing. The kretprobe version missed
    # 282 of 300.
    if isolated:
        check(len(ports) == 300 and not missing,
              f"every bind made beside 400 contending threads is reported "
              f"({missing} of {len(ports)} missing)")
    else:
        print("note: could not give the binds a CPU of their own; "
              "contention case skipped")

    snoop = start_snoop()
    load = subprocess.run([stress, "oversubscribe", "64", "2000"], capture_output=True,
                          text=True, check=True, timeout=300)
    ops = int(load.stdout)
    events = stop_snoop(snoop)
    delivered = sum(1 for e in events if e["kind"] in ("bind", "listen")
                    and e["comm"] == "bind_stress")
    lost = sum(e["count"] for e in events if e["kind"] == "lost")
    check(delivered + lost >= ops,
          f"64 threads on two CPUs: every call is delivered or counted lost "
          f"({ops} calls, {delivered} delivered, {lost} lost)")
    if not lost:
        print("note: no calls skipped on this kernel; the accounting check was vacuous")

    # Nobody reads stdout while 300,000 binds fire, so the buffer overflows.
    snoop = start_snoop(read=False)
    subprocess.run([stress, "flood", "300000"], check=True, timeout=120)
    events = stop_snoop(snoop)
    lost = sum(e["count"] for e in events if e["kind"] == "lost")
    delivered = sum(1 for e in events if e["kind"] == "bind" and e["comm"] == "bind_stress")
    check(lost > 0 and lost + delivered >= 300000,
          f"an overflow is reported as lost ({delivered} delivered, {lost} lost)")

    if failures:
        sys.exit(f"{len(failures)} check(s) failed")
    print(f"all checks passed ({len(expected)} expected events)")


if __name__ == "__main__":
    main()
