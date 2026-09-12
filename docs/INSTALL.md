# Installing GhostPort as a systemd service

This describes running GhostPort as a persistent systemd service on a
supported Linux host (kernel 6.6+, see the README's Requirements section).
It has been exercised end-to-end, including clean shutdown, on a disposable
GitHub Actions Linux runner via `scripts/systemd-integration-test.sh` (also
run by CI) — not on any personal or production machine.

## Install

1. Build or download a release package (see the README's Releases section)
   and extract the `ghostport` binary.

2. Create a dedicated, unprivileged system user. GhostPort never needs to
   run as root; it gets the specific capabilities it needs (see
   [Capabilities](#capabilities)) from the unit file instead.

   ```sh
   sudo useradd --system --no-create-home --shell /usr/sbin/nologin ghostport
   ```

3. Install the binary:

   ```sh
   sudo install -o root -g root -m 0755 ghostport /usr/local/bin/ghostport
   ```

4. Create the configuration directory and files:

   ```sh
   sudo mkdir -p /etc/ghostport
   sudo cp packaging/systemd/ghostport.env.example /etc/ghostport/ghostport.env
   sudo "$EDITOR" /etc/ghostport/ghostport.env   # set GHOSTPORT_INTERFACE at minimum
   sudo chown root:ghostport /etc/ghostport/ghostport.env
   sudo chmod 0640 /etc/ghostport/ghostport.env
   ```

   If you plan to use `--deliver`, also:

   ```sh
   sudo cp packaging/systemd/ghostport-delivery-token.env.example /etc/ghostport/delivery-token.env
   sudo "$EDITOR" /etc/ghostport/delivery-token.env   # set the real token
   sudo chown root:ghostport /etc/ghostport/delivery-token.env
   sudo chmod 0640 /etc/ghostport/delivery-token.env
   ```

5. Install and enable the unit:

   ```sh
   sudo install -m 0644 packaging/systemd/ghostport.service /etc/systemd/system/ghostport.service
   sudo systemctl daemon-reload
   sudo systemctl enable --now ghostport
   ```

6. Verify it is running and attached:

   ```sh
   sudo systemctl status ghostport
   sudo journalctl -u ghostport -f
   ```

## Uninstall

```sh
sudo systemctl disable --now ghostport
sudo rm /etc/systemd/system/ghostport.service
sudo systemctl daemon-reload
sudo rm -rf /etc/ghostport
sudo rm /usr/local/bin/ghostport
sudo userdel ghostport
```

`systemctl stop` (part of `disable --now`) sends `SIGTERM`, which GhostPort
handles by detaching its TCX link and exiting (see
[Clean shutdown](#clean-shutdown)) — no separate cleanup step is needed for
the BPF program itself.

## Upgrade

```sh
sudo systemctl stop ghostport
sudo install -o root -g root -m 0755 ghostport-new /usr/local/bin/ghostport
sudo systemctl start ghostport
```

GhostPort keeps no on-disk state (traffic counters and scan-detection state
live only in memory and the BPF map), so there is nothing to migrate between
versions. Check `ghostport --version` against the release you intended to
install.

## Rollback

Keep the previous binary until an upgrade is confirmed good:

```sh
sudo cp /usr/local/bin/ghostport /usr/local/bin/ghostport.previous
# ... upgrade, then if something is wrong:
sudo systemctl stop ghostport
sudo cp /usr/local/bin/ghostport.previous /usr/local/bin/ghostport
sudo systemctl start ghostport
```

Because there is no persistent on-disk state, rollback is just re-installing
the previous binary and restarting the service.

## Capabilities

GhostPort runs as the unprivileged `ghostport` user with only the Linux
capabilities it actually needs, granted via `AmbientCapabilities` /
`CapabilityBoundingSet` in the unit file, instead of running as root:

| Capability | Why |
|---|---|
| `CAP_BPF` | Load BPF programs and create BPF maps (Linux 5.8+). |
| `CAP_NET_ADMIN` | Attach and detach the TCX ingress link on the target interface. |
| `CAP_PERFMON` | Required by the verifier for some program/map operations on several kernel versions, even for a non-tracing program type like this one. |
| `CAP_SYS_RESOURCE` | Raise `RLIMIT_MEMLOCK` for the BPF map (`rlimit.RemoveMemlock` in `main.go`). |

The unit also sets `NoNewPrivileges`, a `ProtectSystem=strict` / read-only
filesystem sandbox (GhostPort writes nothing to disk at runtime — its only
output is stdout, captured by the journal), `MemoryDenyWriteExecute`,
`RestrictNamespaces`, `LockPersonality`, and a syscall filter scoped to
`@system-service` plus the `bpf` syscall specifically (which is not always
in that group). See `packaging/systemd/ghostport.service` for the complete,
current set.

## Clean shutdown

`systemctl stop` sends `SIGTERM`. GhostPort's signal handling (`main.go`,
via `signal.NotifyContext`) is the same whether it is started by systemd or
run directly at a terminal with `Ctrl+C`: on either signal, it logs
`shutting down and detaching sensor`, sends `STOPPING=1` over `sd_notify`
under systemd, detaches the TCX ingress link, drains any in-flight event
delivery (bounded by a shutdown grace period), and exits.
`scripts/systemd-integration-test.sh` verifies this concretely on real
Linux by checking `bpftool net` shows no GhostPort program attached to the
test interface after `systemctl stop` completes.

## Readiness and liveness

The unit is `Type=notify`: GhostPort sends `READY=1` only after a
successful TCX attach, so `systemctl status` reports "active (running)"
only once the sensor is genuinely observing traffic, not merely once the
process has started. `WatchdogSec=30s` in the unit pairs with GhostPort
pinging `WATCHDOG=1` at less than half that interval; if those pings stop
(a real hang, not just high load), systemd restarts the service via
`Restart=on-failure`. `scripts/systemd-integration-test.sh` checks both:
that the service actually reaches `ActiveState=active` (which requires the
readiness handshake to have worked) and that it accumulates zero restarts
over the test run.
