#!/usr/bin/env bash
set -euo pipefail

# Installs GhostPort as a real systemd service on this (disposable) Linux
# host, starts it, generates traffic, and verifies both that it works
# under systemd and that stopping it detaches the BPF program cleanly.
# Intended for a throwaway CI runner; never run this against a machine you
# care about without reading docs/INSTALL.md first.

cleanup() {
  sudo systemctl stop ghostport 2>/dev/null || true
  sudo systemctl disable ghostport 2>/dev/null || true
  sudo rm -f /etc/systemd/system/ghostport.service
  sudo rm -rf /etc/ghostport
  sudo rm -f /usr/local/bin/ghostport
  sudo systemctl daemon-reload 2>/dev/null || true
  sudo userdel ghostport 2>/dev/null || true
}
trap cleanup EXIT

if ! id ghostport >/dev/null 2>&1; then
  sudo useradd --system --no-create-home --shell /usr/sbin/nologin ghostport
fi

sudo install -o root -g root -m 0755 ./bin/ghostport /usr/local/bin/ghostport

sudo mkdir -p /etc/ghostport
{
  echo "GHOSTPORT_INTERFACE=lo"
  echo "GHOSTPORT_INTERVAL=1s"
  echo "GHOSTPORT_EXTRA_ARGS="
} | sudo tee /etc/ghostport/ghostport.env >/dev/null
sudo chown root:ghostport /etc/ghostport/ghostport.env
sudo chmod 0640 /etc/ghostport/ghostport.env

sudo install -m 0644 packaging/systemd/ghostport.service /etc/systemd/system/ghostport.service
sudo systemctl daemon-reload

if command -v systemd-analyze >/dev/null 2>&1; then
  sudo systemd-analyze verify /etc/systemd/system/ghostport.service
fi

sudo systemctl enable --now ghostport

sleep 2

if ! systemctl is-active --quiet ghostport; then
  echo "ghostport.service did not become active" >&2
  sudo systemctl status ghostport --no-pager >&2 || true
  sudo journalctl -u ghostport --no-pager >&2 || true
  exit 1
fi

if ! sudo journalctl -u ghostport --no-pager | grep -q "sensor attached"; then
  echo "ghostport.service did not log a successful sensor attachment" >&2
  sudo journalctl -u ghostport --no-pager >&2
  exit 1
fi

ping -c 3 127.0.0.1 >/dev/null
sleep 2

if ! sudo journalctl -u ghostport --no-pager | grep -q '"source_ip":"127.0.0.1"'; then
  echo "ghostport.service did not report loopback traffic while running under systemd" >&2
  sudo journalctl -u ghostport --no-pager >&2
  exit 1
fi

# Best-effort, non-fatal: if bpftool is available, confirm the program is
# actually attached at the kernel level (not just per GhostPort's own log).
# The raw output is always printed so a format mismatch is visible in CI
# logs rather than silently making this check meaningless.
bpftool_before=""
if command -v bpftool >/dev/null 2>&1; then
  bpftool_before=$(sudo bpftool net show 2>&1 || true)
  echo "bpftool net show (before stop):"
  echo "$bpftool_before"
fi

sudo systemctl stop ghostport

if ! sudo journalctl -u ghostport --no-pager | grep -q "shutting down and detaching sensor"; then
  echo "ghostport.service did not log a clean shutdown" >&2
  sudo journalctl -u ghostport --no-pager >&2
  exit 1
fi

exit_status=$(systemctl show ghostport --property=ExecMainStatus --value)
if [[ "$exit_status" != "0" ]]; then
  echo "ghostport.service exited with status $exit_status, want 0" >&2
  sudo journalctl -u ghostport --no-pager >&2
  exit 1
fi

if command -v bpftool >/dev/null 2>&1; then
  bpftool_after=$(sudo bpftool net show 2>&1 || true)
  echo "bpftool net show (after stop):"
  echo "$bpftool_after"

  if [[ "$bpftool_before" == "$bpftool_after" ]]; then
    echo "bpftool output for dev lo is identical before and after systemctl stop; this check cannot tell attachment apart from detachment (see raw output above) and is being treated as inconclusive, not a pass" >&2
  elif echo "$bpftool_after" | grep -qi "tcx\|ghostport"; then
    echo "dev lo still shows a tcx/ghostport program attached after systemctl stop" >&2
    exit 1
  else
    echo "bpftool confirms the program is detached from dev lo after stop (output changed from the pre-stop state above)"
  fi
fi

echo "GhostPort ran under systemd, reported loopback traffic, and shut down cleanly"
