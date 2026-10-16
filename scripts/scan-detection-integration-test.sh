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

sudo ./bin/ghostport --interface lo --interval 1s --json \
  --scan-window 10s --scan-vertical-threshold 5 --scan-cooldown 1s \
  >"$output_file" 2>"$log_file" &
sensor_pid=$!

sleep 2

# Probe 8 distinct closed ports on loopback from this same host. Each
# attempt sends a SYN that GhostPort's ingress hook observes regardless of
# whether the connection succeeds, generating a genuine vertical-scan
# pattern: one source, one destination, many distinct destination ports.
for port in 40001 40002 40003 40004 40005 40006 40007 40008; do
  (echo -n > "/dev/tcp/127.0.0.1/$port") 2>/dev/null || true
done

sleep 3

if ! kill -0 "$sensor_pid" 2>/dev/null; then
  echo "GhostPort exited before scan verification" >&2
  cat "$log_file" >&2
  cat "$output_file" >&2
  exit 1
fi

sudo kill -INT "$sensor_pid"
wait "$sensor_pid"
sensor_pid=""

if ! grep -q '"kind":"scan_alert"' "$output_file"; then
  echo "GhostPort did not emit a scan alert for a synthetic vertical scan" >&2
  cat "$log_file" >&2
  cat "$output_file" >&2
  exit 1
fi

if ! grep -q '"type":"vertical"' "$output_file"; then
  echo "GhostPort emitted a scan alert but not of type vertical" >&2
  cat "$output_file" >&2
  exit 1
fi

echo "GhostPort detected a synthetic vertical port scan"
