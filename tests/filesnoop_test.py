#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 DatRail
"""Run the built bpf/filesnoop against real file opens and check what it reports.

Needs root and a BTF-enabled kernel, like the probe itself. A child process
opens files in every way that should, and should not, produce an event; the
test asserts the child gets exactly one event per (file, access), with the
path and flags it used, and nothing for the opens that must stay silent:

- reads, writes, read-write and exec (the program, then the ELF interpreter
  the kernel loads for it) are each reported once per file, however
  often or from how many threads at once the file is opened that way;
- O_CREAT, O_TRUNC and O_APPEND are reported as asked;
- a directory, a device, an O_PATH open and a failed open are not reported;
- a name that isn't UTF-8 keeps its exact bytes in "path_hex";
- a file on overlayfs, as in every container, is reported once, by the path
  the process used: not again for the layer file overlayfs opens beneath it;
- -p leaves out a decoy process;
- when the reader stalls and the buffer overflows, the gap shows up on
  stdout as "lost", and every open is either reported or counted there;
- filesnoop's own opens are not reported.

Usage: sudo python3 tests/filesnoop_test.py [path/to/filesnoop]
"""
import json
import os
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BINARY = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "bpf", "filesnoop")

# Opens files in the directory given as argv[1] and prints the expected
# events as JSON, then execs argv[2] (an exec event for the same PID). Runs
# as its own process so -p can pick it out; everything it needs is imported
# before it waits, so no stray import opens a file after attach.
CHILD = r"""
import json, os, sys, threading
d, prog, overlay = sys.argv[1], sys.argv[2], sys.argv[3]
sys.stdin.readline()  # wait until filesnoop is attached
expected = []

def exp(path, read=False, write=False, exec=False, creat=False, trunc=False,
        append=False):
    expected.append(dict(path=path, read=read, write=write, exec=exec,
                         creat=creat, trunc=trunc, append=append))

a = os.path.join(d, "a.txt")
fd = os.open(a, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
os.write(fd, b"hello\n")
os.close(fd)
exp(a, write=True, creat=True, trunc=True)
for _ in range(3):                     # the same read, three times: one event
    os.close(os.open(a, os.O_RDONLY))
exp(a, read=True)
os.close(os.open(a, os.O_WRONLY | os.O_APPEND))  # write again: no event
os.close(os.open(a, os.O_RDWR))                  # read-write is new
exp(a, read=True, write=True)

b = os.path.join(d, "b.txt")
with open(b, "w") as f:
    f.write("x")
exp(b, write=True, creat=True, trunc=True)
# Eight threads open b to read at once: still one event.
go = threading.Barrier(8)
def reader():
    go.wait()
    for _ in range(50):
        os.close(os.open(b, os.O_RDONLY))
threads = [threading.Thread(target=reader) for _ in range(8)]
for t in threads: t.start()
for t in threads: t.join()
exp(b, read=True)

# Silent: a directory, a device, O_PATH, a failed open.
os.close(os.open(d, os.O_RDONLY | os.O_DIRECTORY))
os.close(os.open("/dev/null", os.O_RDWR))
os.close(os.open(b, os.O_PATH))
try:
    os.open(os.path.join(d, "missing"), os.O_RDONLY)
except FileNotFoundError:
    pass
try:                                   # EEXIST: fails before any open
    os.open(b, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
except FileExistsError:
    pass

# A name that is not UTF-8.
raw = os.path.join(os.fsencode(d), b"\xe9\xff.bin")
os.close(os.open(raw, os.O_WRONLY | os.O_CREAT, 0o600))
exp(raw.hex(), write=True, creat=True)

# overlayfs: a lower-layer file read through the merged directory, then
# written (copied up). One event each, by the merged path.
if overlay != "-":
    o = os.path.join(overlay, "lower.txt")
    os.close(os.open(o, os.O_RDONLY))
    exp(o, read=True)
    os.close(os.open(o, os.O_WRONLY | os.O_APPEND))
    exp(o, write=True, append=True)

print(json.dumps(expected), flush=True)
sys.stdin.readline()  # wait until the parent has read the list
os.execv(prog, [prog])
"""

failures = []


def check(cond, msg):
    if not cond:
        failures.append(msg)
        print("FAIL:", msg)


def start(args):
    proc = subprocess.Popen([BINARY] + args, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)
    line = proc.stderr.readline()
    if "attached" not in line:
        proc.kill()
        sys.exit(f"filesnoop did not attach: {line}{proc.stderr.read()}")
    first = json.loads(proc.stdout.readline())
    check(first.get("kind") == "start", f"first line is not a start record: {first}")
    return proc


def stop(proc):
    proc.send_signal(signal.SIGINT)
    out, err = proc.communicate(timeout=30)
    check(proc.returncode == 0, f"filesnoop exited {proc.returncode}: {err}")
    return [json.loads(l) for l in out.splitlines() if l.strip()]


def mount_overlay(base):
    """An overlay on tmpfs layers (a container root's layers can't be one).
    Returns the merged directory, or None where overlay can't be mounted."""
    layers = os.path.join(base, "layers")
    os.mkdir(layers)
    if subprocess.run(["mount", "-t", "tmpfs", "tmpfs", layers]).returncode:
        return None
    for sub in ("lower", "upper", "work", "merged"):
        os.mkdir(os.path.join(layers, sub))
    with open(os.path.join(layers, "lower", "lower.txt"), "w") as f:
        f.write("from the lower layer\n")
    merged = os.path.join(layers, "merged")
    opts = "lowerdir={0}/lower,upperdir={0}/upper,workdir={0}/work".format(layers)
    if subprocess.run(["mount", "-t", "overlay", "overlay", "-o", opts, merged]).returncode:
        subprocess.run(["umount", layers])
        return None
    return merged


def key(e):
    path = e.get("path_hex") or e["path"]
    return (path,) + tuple(e[k] for k in ("read", "write", "exec", "creat", "trunc", "append"))


def test_exact_events(tmp):
    merged = mount_overlay(tmp)
    if merged is None:
        if os.environ.get("REQUIRE_OVERLAY"):
            sys.exit("overlayfs could not be mounted, and REQUIRE_OVERLAY is set")
        print("note: overlayfs not mountable here; overlay case skipped")
    work = os.path.join(tmp, "work")
    os.mkdir(work)
    prog = os.path.realpath(shutil.which("true"))
    child = subprocess.Popen([sys.executable, "-c", CHILD, work, prog, merged or "-"],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    decoy = subprocess.Popen([sys.executable, "-c",
                              "import sys,os; sys.stdin.readline(); "
                              f"open(os.path.join({work!r}, 'decoy.txt'), 'w').close()"],
                             stdin=subprocess.PIPE, text=True)
    try:
        snoop = start(["-p", str(child.pid)])
        child.stdin.write("go\n"); child.stdin.flush()
        decoy.stdin.write("go\n"); decoy.stdin.flush()
        expected = json.loads(child.stdout.readline())
        decoy.wait(timeout=30)
        child.stdin.write("exec\n"); child.stdin.flush()
        child.wait(timeout=30)
        time.sleep(0.5)
        events = stop(snoop)
    finally:
        if merged:
            subprocess.run(["umount", merged])
            subprocess.run(["umount", os.path.dirname(merged)])

    opens = [e for e in events if e.get("kind") == "open"]
    check(not [e for e in events if e.get("kind") == "lost"], "events were lost")
    check(all(e["pid"] == child.pid for e in opens),
          f"-p let in another process: {[e for e in opens if e['pid'] != child.pid]}")
    roots = (work, merged) if merged else (work,)
    mine = [e for e in opens
            if (bytes.fromhex(e["path_hex"]).decode("utf-8", "surrogateescape")
                if "path_hex" in e else e["path"]).startswith(roots)]
    got = sorted(key(e) for e in mine)
    want = sorted((x["path"],) + tuple(x[k] for k in ("read", "write", "exec", "creat", "trunc", "append"))
                  for x in expected)
    check(got == want, "events for the child's files differ:\n  got  %s\n  want %s" % (got, want))
    for e in mine:
        check(e["comm"] == "python3" or e["comm"].startswith("python"),
              f"unexpected comm {e['comm']}")
        check(isinstance(e["ino"], int) and ":" in e["dev"], f"no dev/ino in {e}")
    check(not [e for e in opens if e["path"] in ("/dev/null", work)],
          "a device or directory open was reported")
    if merged:
        check(not [e for e in opens if "/upper/" in e["path"] or "/lower/" in e["path"]],
              "overlayfs's own open of the layer file was reported")
    # The kernel opens a dynamic binary's ELF interpreter for exec too.
    execs = [e["path"] for e in opens if e["exec"]]
    check(execs[:1] == [prog] and all("/ld-" in p for p in execs[1:]),
          f"expected an exec event for {prog}, then at most its loader: {execs}")
    print(f"exact events: {len(mine)} file events, {len(execs)} exec")


def test_lost_and_self(tmp):
    """Stall the reader while a child opens many distinct files: the overflow
    must be counted on stdout, and reported + lost must cover every open."""
    flood = os.path.join(tmp, "flood")
    os.mkdir(flood)
    n = 40000
    snoop = start([])
    # Don't read stdout: once the pipe is full, filesnoop blocks and the ring
    # buffer overflows.
    subprocess.run([sys.executable, "-c",
                    "import os,sys\n"
                    "d=sys.argv[1]\n"
                    f"for i in range({n}):\n"
                    "    os.close(os.open(os.path.join(d, 'f%06d' % i), os.O_WRONLY|os.O_CREAT, 0o600))\n",
                    flood], check=True)
    events = stop(snoop)
    reported = sum(1 for e in events if e.get("kind") == "open"
                   and e["path"].startswith(flood + "/"))
    lost = sum(e["count"] for e in events if e.get("kind") == "lost")
    check(lost > 0, "a stalled reader lost nothing: the flood was too small to test")
    check(reported + lost >= n, f"{reported} reported + {lost} lost < {n} opens")
    check(not [e for e in events if e.get("kind") == "open" and e["host_pid"] == snoop.pid],
          "filesnoop reported its own opens")
    print(f"lost: {reported} reported, {lost} counted lost, of {n}")


def main():
    if os.geteuid():
        sys.exit("needs root")
    with tempfile.TemporaryDirectory(prefix="filesnoop-test-") as tmp:
        test_exact_events(tmp)
        test_lost_and_self(tmp)
    if failures:
        print(f"{len(failures)} failure(s)")
        sys.exit(1)
    print("ok: filesnoop")


if __name__ == "__main__":
    main()
