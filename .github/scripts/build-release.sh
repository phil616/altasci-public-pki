#!/usr/bin/env bash
# Run from the repository root after the frontend build. Output must not exist.
set -euo pipefail
[[ $# -eq 2 ]] || { echo 'Usage: build-release.sh VERSION OUTPUT_DIR' >&2; exit 1; }
release_tag=$1
asset_dir=$2

# vMAJOR.MINOR.PATCH with optional SemVer prerelease identifiers; no build metadata.
python3 - "$release_tag" <<'PY'
import re
import sys

tag = sys.argv[1]
match = re.fullmatch(r'v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?', tag)
if not match or any(part.isdigit() and len(part) > 1 and part[0] == '0'
                    for part in (match[4] or '').split('.')):
    raise SystemExit('Expected vMAJOR.MINOR.PATCH or vMAJOR.MINOR.PATCH-prerelease (no leading zeroes or build metadata)')
PY

test -s web/dist/index.html
mkdir -- "$asset_dir"
asset_dir=$(cd "$asset_dir" && pwd)
staging=$(mktemp -d)
trap 'rm -rf "$staging"' EXIT

cp LICENSE .env.example doc/pki-console/pki-console.service \
  doc/pki-console/nginx.conf.example scripts/signing-client.py "$staging/"
for arch in amd64 arm64; do
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" GOFLAGS=-mod=vendor GOPROXY=off \
    go build -trimpath -ldflags "-s -w -X main.version=$release_tag" \
      -o "$staging/pki-console" ./cmd/pki-console
  test -s "$staging/pki-console"
  test -x "$staging/pki-console"
  tar -czf "$asset_dir/pki-console-${release_tag}-linux-${arch}.tar.gz" \
    -C "$staging" pki-console LICENSE .env.example pki-console.service \
    nginx.conf.example signing-client.py
done
