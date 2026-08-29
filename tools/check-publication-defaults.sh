#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
command -v git >/dev/null || { echo "git is required" >&2; exit 3; }
pattern='(/Users/[^[:space:]]+|/home/[^[:space:]]+|[A-Za-z0-9.-]+\.internal(:[0-9]+)?)'
for fixture in '/Users/a-developer/project' '/home/a-developer/project' 'service.internal:8443'; do
  printf '%s\n' "$fixture" | grep -Eq "$pattern" || { echo "detector self-test failed: $fixture" >&2; exit 3; }
done
printf 'https://service.example.com\n' | grep -Eq "$pattern" && { echo "detector negative self-test failed" >&2; exit 3; }

allowed_context() {
  local path=$1 line=$2
  case "$line" in
    *host.docker.internal*)
      case "$path" in docs/legacy-rail-guardian-runbook.md|docs/scanner/legacy-rail-guardian-runbook.md|docs/rc-58-railmon-runtimeinteraction-output.md|docs/rc-74-railmon-runtime-monitor-integration.md|rail-collector/README.md|tools/agent-environment-scanner/README.md|tools/agent-environment-scanner/scan_agent_environment.py|tools/skills-scanner/README.md|fastmcp_proxy/proxy.py|fastmcp_proxy/xrail_auth.py|CONTRIBUTING.md|nemoclaw/docker-compose.yml|openclaw/docker-compose.yml|tests/*|tests-python/*) return 0 ;; esac ;;
    *host.openshell.internal*) case "$path" in tests/fixtures/capture.jsonl|policies/datrail-proxy.yaml.template) return 0 ;; esac ;;
    *.internal.example.com*) case "$path" in tests/*|tests-python/*) return 0 ;; esac; [[ "$path" == src/interaction.rs && "$line" == *'json!'* ]] && return 0; [[ "$path" == src/interaction.rs && "$line" == *'assert_eq!'* ]] && return 0 ;;
    */home/node/*) case "$path" in tools/agent-environment-scanner/scan_agent_environment.py|tools/agent-environment-scanner/README.md|tools/skills-scanner/skill_scanner.py|tools/skills-scanner/README.md|nemoclaw/docker-compose.yml|openclaw/docker-compose.yml) return 0 ;; esac ;;
    */home/agent*) [[ "$line" =~ /home/agent(/|[\"\',[:space:]]) ]] && case "$path" in tests/*|tests-python/*) return 0 ;; esac ;;
    *aizawa-metrics.internal*) [[ "$path" == tools/agent-environment-scanner/scan_agent_environment.py && "$line" == *'called `aizawa-metrics.internal`'* ]] && return 0 ;;
  esac
  return 1
}
allowed_context tests/fixture.py 'url = "https://api.internal.example.com"' || { echo "positive self-test failed" >&2; exit 3; }
allowed_context tests/fixture.py 'url = "http://host.docker.internal:8080"' || { echo "docker-host self-test failed" >&2; exit 3; }
allowed_context tests/fixtures/capture.jsonl 'host = "host.openshell.internal:8091"' || { echo "openshell self-test failed" >&2; exit 3; }
allowed_context tools/agent-environment-scanner/scan_agent_environment.py 'path = "/home/node/.openclaw"' || { echo "node-home self-test failed" >&2; exit 3; }
allowed_context tests/fixture.py 'pwd = "/home/agent"' || { echo "agent-home self-test failed" >&2; exit 3; }
allowed_context tools/agent-environment-scanner/scan_agent_environment.py 'called `aizawa-metrics.internal`' || { echo "aizawa self-test failed" >&2; exit 3; }
if allowed_context src/app.py 'url = "https://api.internal.example.com"'; then echo "negative self-test failed" >&2; exit 3; fi
if allowed_context src/app.py 'url = "http://host.docker.internal:8080"'; then echo "local-address self-test failed" >&2; exit 3; fi
if allowed_context tests/fixture.py 'pwd = "/home/agentsight"'; then echo "agent-home boundary self-test failed" >&2; exit 3; fi
set +e
# Only tracked files can be published from this repository, so scan the index.
hits=$(git -C "$root" grep -n -I -E "$pattern" -- ':!tools/check-publication-defaults.sh')
scan_rc=$?
set -e
(( scan_rc <= 1 )) || { echo "publication-default scan failed (exit $scan_rc)" >&2; exit 3; }
failures=
while IFS= read -r hit; do [[ -z "$hit" ]] && continue; path=${hit%%:*}; line=${hit#*:}; line=${line#*:}; allowed_context "$path" "$line" || failures+="$hit"$'\n'; done <<< "$hits"
[[ -z "$failures" ]] || { printf '%s' "$failures" >&2; exit 1; }
echo "publication-default scan passed"
