#!/usr/bin/env bash
# Source from a private acceptance working directory. See doc/pki-console/manual-acceptance.md.
# This is a client helper; it does not run the acceptance plan automatically.

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  echo 'Source this file from the acceptance working directory.' >&2
  exit 2
fi

_qa_name() { [[ $1 =~ ^[a-zA-Z0-9_-]+$ ]]; }

qa_http() {
  # ROLE METHOD PATH EXPECTED_STATUS OUTPUT [JSON_FILE] [IDEMPOTENCY_KEY]
  [[ $# -ge 5 && $# -le 7 ]] || { echo 'Invalid qa_http arguments' >&2; return 2; }
  local role=$1 method=$2 path=$3 expected=$4 output=$5 body=${6:-} key=${7:-}
  local base status
  _qa_name "$role" && [[ $path == /* && $path != //* ]] || return 2
  local -a args=(--silent --show-error --proto '=https' --connect-timeout 5 --max-time 30)
  case "$role" in
    public) base=${PUBLIC:?Set PUBLIC} ;;
    token-*)
      base=${PUBLIC:?Set PUBLIC}
      [[ -s .secrets/$role.headers ]] || { echo 'Missing Bearer header file' >&2; return 2; }
      args+=(--header "@.secrets/$role.headers") ;;
    *)
      base=${CONSOLE:?Set CONSOLE}
      args+=(--header "Origin: ${QA_ORIGIN:-$CONSOLE}")
      if [[ $role != anonymous ]]; then
        [[ -s .secrets/$role.cookies && -s .secrets/$role.headers ]] || {
          echo 'Run qa_login for this role first' >&2; return 2;
        }
        args+=(--cookie ".secrets/$role.cookies")
        if [[ ${QA_NO_CSRF:-0} != 1 ]]; then args+=(--header "@.secrets/$role.headers"); fi
      fi ;;
  esac
  [[ $base == https://* && $base != */ ]] || { echo 'Use an HTTPS origin without a trailing slash' >&2; return 2; }
  if [[ -n $body ]]; then
    [[ -f $body ]] || { echo 'Missing JSON body file' >&2; return 2; }
    args+=(--header 'Content-Type: application/json' --data-binary "@$body")
  fi
  if [[ $method != GET && $method != HEAD ]]; then
    if [[ -z $key ]]; then key=$(python3 -c 'import uuid; print(uuid.uuid4())') || return; fi
    args+=(--header "Idempotency-Key: $key")
  fi
  mkdir -p -- "$(dirname "$output")" || return
  status=$(curl "${args[@]}" --request "$method" --dump-header "$output.headers" \
    --output "$output" --write-out '%{http_code}' "$base$path") || return
  if [[ $status != "$expected" ]]; then
    printf 'FAIL %s %s: expected HTTP %s, got %s; inspect %s\n' "$method" "$path" "$expected" "$status" "$output" >&2
    return 1
  fi
  printf 'PASS HTTP %s %s %s -> %s\n' "$status" "$method" "$path" "$output"
}

qa_login() {
  # LOCAL_ROLE LOGIN_NAME. The password is read from the terminal, never argv.
  [[ $# == 2 ]] && _qa_name "$1" || return 2
  local role=$1 login=$2 status request=".secrets/$1.request.json"
  [[ ${CONSOLE:-} == https://* && $CONSOLE != */ ]] || return 2
  mkdir -p .secrets || return
  chmod 700 .secrets || return
  python3 - "$request" "$login" <<'PY' || return
import getpass, json, os, sys
password = getpass.getpass("Acceptance account password: ")
fd = os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w") as out:
    json.dump({"login": sys.argv[2], "password": password}, out)
PY
  status=$(curl --silent --show-error --proto '=https' --connect-timeout 5 --max-time 30 \
    --header "Origin: $CONSOLE" --header 'Content-Type: application/json' \
    --cookie-jar ".secrets/$role.cookies" --data-binary "@$request" \
    --output ".secrets/$role.login.json" --write-out '%{http_code}' "$CONSOLE/api/v1/auth/login")
  local curl_status=$?
  python3 - "$request" <<'PY'
import pathlib, sys
pathlib.Path(sys.argv[1]).unlink()
PY
  if [[ $curl_status != 0 || $status != 200 ]]; then
    printf 'FAIL login: HTTP %s; inspect .secrets/%s.login.json\n' "$status" "$role" >&2
    return 1
  fi
  local csrf
  csrf=$(jq -er '.csrf_token | select(type=="string" and length>0)' ".secrets/$role.login.json") || return
  printf 'X-CSRF-Token: %s\n' "$csrf" > ".secrets/$role.headers"
  chmod 600 ".secrets/$role.cookies" ".secrets/$role.login.json" ".secrets/$role.headers"
  printf 'PASS login %s (client alias %s)\n' "$login" "$role"
}

qa_check() {
  # LABEL COMMAND [ARG ...]. Saves command output, preserving its exit status.
  [[ $# -ge 2 ]] && _qa_name "$1" || return 2
  local label=$1
  shift
  mkdir -p evidence || return
  if LC_ALL=C "$@" > "evidence/$label.log" 2>&1; then
    printf 'PASS %s\n' "$label"
  else
    printf 'FAIL %s; inspect evidence/%s.log\n' "$label" "$label" >&2
    return 1
  fi
}

qa_reject() {
  # LABEL REQUIRED_ERROR_TEXT COMMAND [ARG ...]. Failure alone is insufficient.
  [[ $# -ge 3 ]] && _qa_name "$1" || return 2
  local label=$1 pattern=$2
  shift 2
  mkdir -p evidence || return
  if LC_ALL=C "$@" > "evidence/$label.log" 2>&1; then
    printf 'FAIL %s: command unexpectedly succeeded\n' "$label" >&2
    return 1
  fi
  if grep -Fq -- "$pattern" "evidence/$label.log"; then
    printf 'PASS expected rejection: %s\n' "$label"
  else
    printf 'FAIL %s: wrong rejection; inspect evidence/%s.log\n' "$label" "$label" >&2
    return 1
  fi
}
