#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <amd64|arm64> <version>" >&2
  exit 2
fi

architecture=$1
version=${2//\//-}
case "$architecture" in
  amd64|arm64) ;;
  *)
    echo "unsupported architecture: $architecture" >&2
    exit 2
    ;;
esac

package_name="ghostport-${version}-linux-${architecture}"
stage_dir="dist/${package_name}"

rm -rf "$stage_dir"
mkdir -p "$stage_dir"

CGO_ENABLED=0 GOOS=linux GOARCH="$architecture" go build \
  -trimpath \
  -ldflags="-s -w -X main.version=${version}" \
  -o "$stage_dir/ghostport" \
  ./cmd/ghostport

cp README.md "$stage_dir/"
tar -C dist -czf "dist/${package_name}.tar.gz" "$package_name"
rm -rf "$stage_dir"

echo "Created dist/${package_name}.tar.gz"
