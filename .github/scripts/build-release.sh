#!/usr/bin/env bash
# Run from the repository root after the frontend build. Output must not exist.
set -euo pipefail
[[ $# -eq 2 ]] || { echo 'Usage: build-release.sh VERSION OUTPUT_DIR' >&2; exit 1; }
release_tag=$1
asset_dir=$2

# vMAJOR.MINOR.PATCH with optional SemVer prerelease identifiers; no build metadata.
python3 "$(dirname "${BASH_SOURCE[0]}")/validate-release-tag.py" "$release_tag"

test -s web/dist/index.html
mkdir -p -- "$(dirname "$asset_dir")"
mkdir -- "$asset_dir"
asset_dir=$(cd "$asset_dir" && pwd)
staging=$(mktemp -d)
trap 'rm -rf "$staging"' EXIT

cp console/store/schema.sql "$staging/schema.sql"
cp doc/pki-console/distribution-README.md "$staging/README.md"
cp LICENSE .env.example doc/pki-console/pki-console.service \
  doc/pki-console/nginx.conf.example scripts/signing-client.py "$staging/"
for arch in amd64 arm64; do
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" GOFLAGS=-mod=vendor GOPROXY=off \
    go build -trimpath -ldflags "-s -w -X main.version=$release_tag" \
      -o "$staging/pki-console" ./cmd/pki-console
  test -s "$staging/pki-console"
  test -x "$staging/pki-console"
  tar -czf "$asset_dir/pki-console-${release_tag}-linux-${arch}.tar.gz" \
    -C "$staging" pki-console README.md schema.sql LICENSE .env.example pki-console.service \
    nginx.conf.example signing-client.py
done

(cd "$asset_dir" && sha256sum pki-console-*.tar.gz > SHA256SUMS)
