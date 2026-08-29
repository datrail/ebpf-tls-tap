#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
command -v git >/dev/null || { echo "git is required" >&2; exit 3; }
# Match only the home root and account name. Paths may contain essentially any
# punctuation, so consuming the tail makes one occurrence swallow the next.
home_pattern='(/Users/(\[[^]]+\]|\$[A-Za-z_][A-Za-z0-9_]*|[[:alnum:]_.-]+)|/home/(\[[^]]+\]|\$[A-Za-z_][A-Za-z0-9_]*|[[:alnum:]_.-]+))'
internal_pattern='[A-Za-z0-9.-]+\.internal(\.[A-Za-z0-9.-]+)*(:[0-9]+)?'
pattern="($home_pattern|$internal_pattern)"

allowed_match() {
  local LC_ALL=C path=$1 line=$2 match=${3,,} offset=$4 before after
  before=${line:0:offset}
  after=${line:offset+${#3}}
  case "$match" in
    host.docker.internal|host.docker.internal:[0-9]*)
      case "$path" in docs/legacy-rail-guardian-runbook.md|docs/scanner/legacy-rail-guardian-runbook.md|docs/rc-58-railmon-runtimeinteraction-output.md|docs/rc-74-railmon-runtime-monitor-integration.md|rail-collector/README.md|tools/agent-environment-scanner/README.md|tools/agent-environment-scanner/scan_agent_environment.py|tools/skills-scanner/README.md|fastmcp_proxy/proxy.py|fastmcp_proxy/xrail_auth.py|CONTRIBUTING.md|nemoclaw/docker-compose.yml|openclaw/docker-compose.yml|tests/*|tests-python/*) return 0 ;; esac ;;
    host.openshell.internal|host.openshell.internal:[0-9]*)
      case "$path" in tests/fixtures/capture.jsonl|policies/datrail-proxy.yaml.template) return 0 ;; esac ;;
    *.internal.example.com|*.internal.example.com:[0-9]*)
      case "$path" in tests/*|tests-python/*) return 0 ;; esac
      ;;
    /home/node)
      case "$path" in tools/agent-environment-scanner/scan_agent_environment.py|tools/agent-environment-scanner/README.md|tools/skills-scanner/skill_scanner.py|tools/skills-scanner/README.md|nemoclaw/docker-compose.yml|openclaw/docker-compose.yml) return 0 ;; esac ;;
    /home/agent|/home/agent/*)
      case "$path" in tests/*|tests-python/*) return 0 ;; esac ;;
    aizawa-metrics.internal)
      [[ "$path" == tools/agent-environment-scanner/scan_agent_environment.py &&
        "$before" == *'called `'
        && "$after" == \`* ]] && return 0 ;;
  esac
  if [[ "$path" == src/interaction.rs && "$match" == *.internal.example.com ]]; then
    [[ "$before" == *'json!("https://' && "$after" == '/v1/messages?beta=true")'* ]] && return 0
    [[ "$before" == *'assert_eq!(out["request"]["destination"], "' && "$after" == '");'* ]] && return 0
  fi
  return 1
}

parse_scan_output() {
  local output=$1 matches=$2 path= lineno= line= match record offset detector detector_rc failures=
  while :; do
    path=
    if ! IFS= read -r -d '' path; then
      [[ -z "$path" ]] || { echo "publication-default scan returned a partial path record" >&2; return 3; }
      break
    fi
    lineno=
    IFS= read -r -d '' lineno || { echo "publication-default scan returned a partial line-number record" >&2; return 3; }
    line=
    IFS= read -r line || { echo "publication-default scan returned a partial line record" >&2; return 3; }
    : >"$matches"
    for detector in "$home_pattern" "$internal_pattern"; do
      if printf '%s\n' "$line" | grep -b -o -i -E "$detector" >>"$matches"; then detector_rc=0; else detector_rc=$?; fi
      (( detector_rc <= 1 )) || { echo "publication-default match extraction failed (exit $detector_rc)" >&2; return 3; }
    done
    [[ -s "$matches" ]] || { echo "publication-default match extraction returned no matches" >&2; return 3; }
    while IFS= read -r record; do
      offset=${record%%:*}
      match=${record#*:}
      [[ "$offset" =~ ^[0-9]+$ && -n "$match" ]] || { echo "publication-default match extraction returned a malformed match" >&2; return 3; }
      allowed_match "$path" "$line" "$match" "$offset" || failures+="$path:$lineno:$match"$'\n'
    done <"$matches"
  done <"$output"
  [[ -z "$failures" ]] || { printf '%s' "$failures" >&2; return 1; }
}

scan_index() (
  local repo=$1 temporary output matches scan_rc parse_rc
  temporary=$(mktemp -d)
  trap 'rc=$?; trap - EXIT; rm -rf -- "$temporary" || rc=3; exit "$rc"' EXIT
  output="$temporary/output"
  matches="$temporary/matches"
  if git -C "$repo" grep --cached -z -n -I -i -E "$pattern" -- ':!tools/check-publication-defaults.sh' >"$output"; then
    scan_rc=0
  else
    scan_rc=$?
  fi
  if (( scan_rc > 1 )); then
    echo "publication-default scan failed (exit $scan_rc)" >&2
    return 3
  fi
  if parse_scan_output "$output" "$matches"; then parse_rc=0; else parse_rc=$?; fi
  return "$parse_rc"
)

self_test() (
  local fixture index rc output expected path content unicode_prefix
  fixture=$(mktemp -d)
  trap 'rc=$?; trap - EXIT; rm -rf -- "$fixture" || rc=3; exit "$rc"' EXIT
  index="$fixture/index"
  git -C "$fixture" init -q
  mkdir -p "$fixture/tests" "$fixture/tools/agent-environment-scanner"
  printf -v unicode_prefix 'é%.0s' {1..31}

  check_case() {
    local name=$1 case_path=$2 case_content=$3 expected_rc=$4 expected_output=$5
    GIT_INDEX_FILE="$index" git -C "$fixture" read-tree --empty
    mkdir -p "$fixture/$(dirname "$case_path")"
    printf '%s\n' "$case_content" >"$fixture/$case_path"
    GIT_INDEX_FILE="$index" git -C "$fixture" add "$case_path"
    if output=$(GIT_INDEX_FILE="$index" scan_index "$fixture" 2>&1); then rc=0; else rc=$?; fi
    if [[ $rc -ne $expected_rc || "$output" != "$expected_output" ]]; then
      printf '%s self-test failed (exit %s, output %q)\n' "$name" "$rc" "$output" >&2
      return 3
    fi
  }

  check_case case-insensitive tests/fixture.py 'SERVICE.INTERNAL' 1 'tests/fixture.py:1:SERVICE.INTERNAL' || return
  check_case later-match tests/fixture.py 'host.docker.internal secret.internal' 1 'tests/fixture.py:1:secret.internal' || return
  check_case colon-filename 'tests/allowed:fixture.py' 'secret.internal' 1 'tests/allowed:fixture.py:1:secret.internal' || return
  check_case comma-delimiter tools/agent-environment-scanner/scan_agent_environment.py '/home/node/.openclaw,endpoint=secret.internal' 1 'tools/agent-environment-scanner/scan_agent_environment.py:1:secret.internal' || return
  check_case colon-delimiter tools/agent-environment-scanner/scan_agent_environment.py '/home/node/work:/home/private-user/project' 1 'tools/agent-environment-scanner/scan_agent_environment.py:1:/home/private-user' || return
  check_case equals-delimiter tools/agent-environment-scanner/scan_agent_environment.py '/home/node/work=/home/private-user/project' 1 'tools/agent-environment-scanner/scan_agent_environment.py:1:/home/private-user' || return
  check_case slash-delimiter tools/agent-environment-scanner/scan_agent_environment.py '/home/node/.openclaw/secret.internal' 1 'tools/agent-environment-scanner/scan_agent_environment.py:1:secret.internal' || return
  check_case punctuation-delimiter tools/agent-environment-scanner/scan_agent_environment.py '/home/node/.openclaw;secret.internal' 1 'tools/agent-environment-scanner/scan_agent_environment.py:1:secret.internal' || return
  for content in '/home/node/ok;/home/private-user/project' '/home/node/ok//home/private-user/project' '/home/node/ok?/home/private-user/project' '/home/node/ok&/home/private-user/project' "/home/node/ok'/home/private-user/project"; do
    check_case home-only-boundary tools/agent-environment-scanner/scan_agent_environment.py "$content" 1 'tools/agent-environment-scanner/scan_agent_environment.py:1:/home/private-user' || return
  done
  check_case bracket-home tests/fixture.py '/home/[private-user]/project' 1 'tests/fixture.py:1:/home/[private-user]' || return
  check_case variable-home tests/fixture.py '/home/$USER/project' 1 'tests/fixture.py:1:/home/$USER' || return
  check_case unicode-home tests/fixture.py '/home/开发者/project' 1 'tests/fixture.py:1:/home/开发者' || return
  check_case aizawa-context tools/agent-environment-scanner/scan_agent_environment.py 'The service is called `aizawa-metrics.internal` for compatibility.' 0 '' || return
  check_case aizawa-real tools/agent-environment-scanner/scan_agent_environment.py 'endpoint = "aizawa-metrics.internal"' 1 'tools/agent-environment-scanner/scan_agent_environment.py:1:aizawa-metrics.internal' || return
  check_case aizawa-repeated tools/agent-environment-scanner/scan_agent_environment.py 'The service is called `aizawa-metrics.internal`; endpoint="aizawa-metrics.internal"' 1 'tools/agent-environment-scanner/scan_agent_environment.py:1:aizawa-metrics.internal' || return
  check_case aizawa-unicode-offset tools/agent-environment-scanner/scan_agent_environment.py "${unicode_prefix}aizawa-metrics.internalcalled \`XXXXXXXXXXXXXXXXXXXXXXX\`" 1 'tools/agent-environment-scanner/scan_agent_environment.py:1:aizawa-metrics.internal' || return
  check_case rust-json-exact src/interaction.rs 'let v = json!("https://proxy.internal.example.com/v1/messages?beta=true"); endpoint="evil.internal.example.com";' 1 'src/interaction.rs:1:evil.internal.example.com' || return
  check_case rust-assert-exact src/interaction.rs 'assert_eq!(out["request"]["destination"], "proxy.internal.example.com"); endpoint="evil.internal.example.com";' 1 'src/interaction.rs:1:evil.internal.example.com' || return
  check_case allowed tests/fixture.py 'host.docker.internal:8080 api.internal.example.com /home/agent' 0 '' || return
  check_case negative tests/fixture.py 'https://service.example.com /opt/app' 0 '' || return

  GIT_INDEX_FILE="$index" git -C "$fixture" read-tree --empty
  printf '%s\n' 'secret.internal' >"$fixture/tests/fixture.py"
  GIT_INDEX_FILE="$index" git -C "$fixture" add tests/fixture.py
  printf '%s\n' 'https://service.example.com' >"$fixture/tests/fixture.py"
  if output=$(GIT_INDEX_FILE="$index" scan_index "$fixture" 2>&1); then rc=0; else rc=$?; fi
  [[ $rc -eq 1 && "$output" == 'tests/fixture.py:1:secret.internal' ]] || { echo "index-scope self-test failed" >&2; return 3; }

  output="$fixture/partial-output"
  expected="$fixture/partial-matches"
  printf 'tests/fixture.py' >"$output"
  if path=$(parse_scan_output "$output" "$expected" 2>&1); then rc=0; else rc=$?; fi
  [[ $rc -eq 3 && "$path" == 'publication-default scan returned a partial path record' ]] || { echo "partial-path-record self-test failed" >&2; return 3; }

  printf 'tests/fixture.py\0001' >"$output"
  if path=$(parse_scan_output "$output" "$expected" 2>&1); then rc=0; else rc=$?; fi
  [[ $rc -eq 3 && "$path" == 'publication-default scan returned a partial line-number record' ]] || { echo "partial-line-number-record self-test failed" >&2; return 3; }

  printf 'tests/fixture.py\0001\000secret.internal' >"$output"
  if path=$(parse_scan_output "$output" "$expected" 2>&1); then rc=0; else rc=$?; fi
  [[ $rc -eq 3 && "$path" == 'publication-default scan returned a partial line record' ]] || { echo "partial-line-record self-test failed" >&2; return 3; }

  if output=$(scan_index "$fixture/not-a-repository" 2>&1); then rc=0; else rc=$?; fi
  [[ $rc -eq 3 && "$output" == *'publication-default scan failed (exit 128)' ]] || { echo "scan-error self-test failed" >&2; return 3; }
)

self_test
# Scan the index explicitly: only staged tracked content can be published.
scan_index "$root"
echo "publication-default scan passed"
