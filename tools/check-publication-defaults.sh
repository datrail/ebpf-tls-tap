#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
command -v git >/dev/null || { echo "git is required" >&2; exit 3; }
pattern='(/Users/[A-Za-z0-9._~@%+=:,/-]+|/home/[A-Za-z0-9._~@%+=:,/-]+|[A-Za-z0-9.-]+\.internal(\.[A-Za-z0-9.-]+)*(:[0-9]+)?)'

allowed_match() {
  local path=$1 match=${2,,}
  case "$match" in
    host.docker.internal|host.docker.internal:[0-9]*)
      case "$path" in docs/legacy-rail-guardian-runbook.md|docs/scanner/legacy-rail-guardian-runbook.md|docs/rc-58-railmon-runtimeinteraction-output.md|docs/rc-74-railmon-runtime-monitor-integration.md|rail-collector/README.md|tools/agent-environment-scanner/README.md|tools/agent-environment-scanner/scan_agent_environment.py|tools/skills-scanner/README.md|fastmcp_proxy/proxy.py|fastmcp_proxy/xrail_auth.py|CONTRIBUTING.md|nemoclaw/docker-compose.yml|openclaw/docker-compose.yml|tests/*|tests-python/*) return 0 ;; esac ;;
    host.openshell.internal|host.openshell.internal:[0-9]*)
      case "$path" in tests/fixtures/capture.jsonl|policies/datrail-proxy.yaml.template) return 0 ;; esac ;;
    *.internal.example.com|*.internal.example.com:[0-9]*)
      case "$path" in tests/*|tests-python/*|src/interaction.rs) return 0 ;; esac ;;
    /home/node/*)
      case "$path" in tools/agent-environment-scanner/scan_agent_environment.py|tools/agent-environment-scanner/README.md|tools/skills-scanner/skill_scanner.py|tools/skills-scanner/README.md|nemoclaw/docker-compose.yml|openclaw/docker-compose.yml) return 0 ;; esac ;;
    /home/agent|/home/agent/*)
      case "$path" in tests/*|tests-python/*) return 0 ;; esac ;;
    aizawa-metrics.internal)
      [[ "$path" == tools/agent-environment-scanner/scan_agent_environment.py ]] && return 0 ;;
  esac
  return 1
}

scan_index() {
  local repo=$1 output path lineno match scan_rc failures=
  output=$(mktemp)
  if git -C "$repo" grep -z -n -I -o -i -E "$pattern" -- ':!tools/check-publication-defaults.sh' >"$output"; then
    scan_rc=0
  else
    scan_rc=$?
  fi
  (( scan_rc <= 1 )) || { echo "publication-default scan failed (exit $scan_rc)" >&2; return 3; }
  while IFS= read -r -d '' path && IFS= read -r -d '' lineno && IFS= read -r match; do
    allowed_match "$path" "$match" || failures+="$path:$lineno:$match"$'\n'
  done <"$output"
  [[ -z "$failures" ]] || { printf '%s' "$failures" >&2; return 1; }
}

self_test() {
  local fixture index rc
  fixture=$(mktemp -d)
  index="$fixture/index"
  git -C "$fixture" init -q
  mkdir -p "$fixture/tests"
  printf '%s\n' \
    'host.docker.internal /home/private-user/project' \
    'api.internal.example.com secret.internal' \
    '/home/node/.openclaw secret.internal' \
    'SERVICE.INTERNAL Service.Internal:8443' >"$fixture/tests/fixture.py"
  printf '%s\n' 'host.docker.internal' >"$fixture/tests/allowed:fixture.py"
  GIT_INDEX_FILE="$index" git -C "$fixture" add tests/fixture.py 'tests/allowed:fixture.py'
  if GIT_INDEX_FILE="$index" scan_index "$fixture" >/dev/null 2>&1; then rc=0; else rc=$?; fi
  [[ $rc -eq 1 ]] || { echo "mixed-match self-test failed (exit $rc)" >&2; return 3; }
  printf '%s\n' 'host.docker.internal:8080 api.internal.example.com /home/agent' >"$fixture/tests/fixture.py"
  GIT_INDEX_FILE="$index" git -C "$fixture" add tests/fixture.py
  GIT_INDEX_FILE="$index" scan_index "$fixture" || { echo "allowed-match self-test failed" >&2; return 3; }
  printf '%s\n' 'https://service.example.com /opt/app' >"$fixture/tests/fixture.py"
  GIT_INDEX_FILE="$index" git -C "$fixture" add tests/fixture.py
  GIT_INDEX_FILE="$index" scan_index "$fixture" || { echo "negative detector self-test failed" >&2; return 3; }
  if scan_index "$fixture/not-a-repository" >/dev/null 2>&1; then rc=0; else rc=$?; fi
  [[ $rc -eq 3 ]] || { echo "scan-error self-test failed (exit $rc)" >&2; return 3; }
}

self_test
# git grep searches the index by default: only tracked content can be published.
scan_index "$root"
echo "publication-default scan passed"
