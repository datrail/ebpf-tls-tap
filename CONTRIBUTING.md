# Contributing to eBPF TLS tap

This builds `sslsniff`: uprobes on a process's TLS library that read plaintext before encryption, and emit it as JSONL for RailMon.

## Before you write code

Open an issue first for anything beyond an obvious fix. Kernel-side changes deserve an issue first — the review is slower and the failure modes are host-wide.

## What to be careful about

**Kernel code is different.** Anything the verifier accepts can still crash or
leak on a kernel you did not test. State which kernels you ran it on.

**Do not change the licence markers in passing.** `bpf/sslsniff.bpf.c` declares
`SEC("license") = "GPL"` to the verifier; the LICENSE file and the SPDX headers
currently disagree with it, and untangling that is DR-21. Leave all three alone
unless that is the change you are making.

**The tap handles plaintext.** Anything that widens where captured data goes
needs to be deliberate and discussed.

## Sending a change

- One coherent change per pull request, with a message that says *why* — the
  diff already says what.
- Branch from `master`.
- **Sign off your commits** (`git commit -s`). We use the
  [Developer Certificate of Origin](https://developercertificate.org/); the
  sign-off is your statement that you wrote the change or have the right to
  contribute it. No CLA.

## Reporting a vulnerability

Not here — see [SECURITY.md](SECURITY.md), and please do not open a public
issue.
