#!/usr/bin/env bash
set -euo pipefail

output_file=$(mktemp)
log_file=$(mktemp)
sensor_pid=""

cleanup() {
  if [[ -n "$sensor_pid" ]] && kill -0 "$sensor_pid" 2>/dev/null; then
    sudo kill -INT "$sensor_pid" 2>/dev/null || true
    wait "$sensor_pid" 2>/dev/null || true
  fi
  rm -f "$output_file" "$log_file"
}
trap cleanup EXIT

sudo ./bin/ghostport --interface lo --interval 1s --json >"$output_file" 2>"$log_file" &
sensor_pid=$!

sleep 2
ping -c 3 127.0.0.1 >/dev/null
sleep 2

if ! kill -0 "$sensor_pid" 2>/dev/null; then
  echo "GhostPort exited before traffic verification" >&2
  cat "$log_file" >&2
  cat "$output_file" >&2
  exit 1
fi

sudo kill -INT "$sensor_pid"
wait "$sensor_pid"
sensor_pid=""

if ! grep -q '"source_ip":"127.0.0.1"' "$output_file"; then
  echo "GhostPort did not report generated loopback traffic" >&2
  cat "$log_file" >&2
  cat "$output_file" >&2
  exit 1
fi

echo "GhostPort observed generated loopback traffic"
