# Security Policy

This repository builds `sslsniff`, which attaches uprobes to a process's TLS
library and reads **plaintext before it is encrypted**. It runs privileged, and
part of it runs **in the kernel**.

Two consequences worth being blunt about: a bug here can be a host-level
compromise rather than an application one, and the data it handles is the
unencrypted contents of somebody's agent traffic.

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Email **yusheng@railxia.com** with `SECURITY` in the subject.

GitHub's private vulnerability reporting is not available here yet — it is a
public-repository feature and these repos are still private. It becomes the
preferred channel once that changes.

Include what an attacker can do (not only what is wrong), the version or commit,
the smallest reproduction you have, and whether you have told anyone else.

## What to expect

| | |
| --- | --- |
| Acknowledgement | within 3 working days |
| First assessment | within 10 working days |
| Progress | at least every 10 working days until it closes |

We ask for **90 days** before public disclosure and will usually be much
faster. You will be credited unless you would rather not be, and if we disagree
that a report is a vulnerability we will say so plainly rather than let it go
quiet.

## What matters most here

- **Anything reachable by the kernel verifier.** A BPF program that can be made
  to read out of bounds, leak kernel memory into userspace, or crash the host is
  the most serious thing this repository can contain.
- **Privilege.** The loader needs `CAP_BPF`/`CAP_SYS_ADMIN` or root. Anything
  that lets a less privileged process influence what is attached, or what the
  loader does with what it reads, is in scope.
- **The captured plaintext itself.** It is written to stdout as JSONL and
  consumed by RailMon. Anything that causes it to reach somewhere else, or to be
  retained where it should not be, is in scope.

## Scope

Out of scope, but tell us if it looks serious: vulnerabilities in libbpf, BCC or
the kernel itself (report those upstream — we will help route them), and the
fact that capture requires privilege, which is inherent to what this does.

## A licensing note, relevant to contributors

`bpf/sslsniff.bpf.c` declares `char LICENSE[] SEC("license") = "GPL"` — a
statement to the kernel verifier, and what permits the program to call GPL-only
helpers. The repository's LICENSE file and its SPDX headers currently disagree
with that and with each other; resolving it is tracked as DR-21. Do not change
any of the three in passing.
