#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
command -v rg >/dev/null || { echo "rg is required" >&2; exit 3; }
printf '/home/a-developer/project\n' | rg -q --pcre2 '/home/(?!node(?:/|$)|runner(?:/|$))[^ /]+' || { echo "scanner self-test failed" >&2; exit 3; }
set +e
hits=$(rg -n --hidden --pcre2 '(/Users/[^ /]+|/home/(?!node(?:/|$)|runner(?:/|$))[^ /]+|(?<!host\.docker)(?<!host\.openshell)[A-Za-z0-9.-]+\.internal(:[0-9]+)?)' "$root" --glob '!**/.git/**' --glob '!**/tests*/**' --glob '!**/docs/**' --glob '!**/examples/**' --glob '!**/*.example' --glob '!**/check-publication-defaults.sh' --glob '!**/tools/agent-environment-scanner/**' --glob '!**/tools/skills-scanner/**' --glob '!**/ebpf-tls-tap/**' --glob '!**/bpftool/**' --glob '!**/libbpf/**' --glob '!**/vmlinux/**')
scan_rc=$?
filtered=$(printf '%s\n' "$hits" | rg -v 'host\.(docker|openshell)\.internal|proxy\.internal|/README\.md:')
filter_rc=$?
set -e
(( scan_rc <= 1 )) || { echo "publication-default scan failed (exit $scan_rc)" >&2; exit 3; }
(( filter_rc <= 1 )) || { echo "publication-default allowlist failed (exit $filter_rc)" >&2; exit 3; }
hits="$filtered"
[[ -z "$hits" ]] || { echo "$hits" >&2; exit 1; }
echo "publication-default scan passed"
