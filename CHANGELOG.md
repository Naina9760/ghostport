# Changelog

All notable changes to GhostPort are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). No version has
been tagged yet; everything below is unreleased.

## [Unreleased]

### Added

- IPv4 ingress traffic sensor: an eBPF TCX program attached to a chosen
  interface, reporting cumulative packet counts by source address,
  destination address, protocol, and destination port, in text or
  newline-delimited JSON.
- Vertical and horizontal port-scan detection, in userspace, on top of that
  traffic telemetry: configurable window, thresholds, and alert cooldown;
  versioned (`schema_version`) structured `scan_alert` JSON events with no
  packet payloads.
- Optional authenticated HTTPS delivery of scan alerts to a configurable
  endpoint: disabled by default, token via `GHOSTPORT_DELIVERY_TOKEN` only
  (never a CLI flag), strict TLS validation, bounded retries with jitter,
  bounded queue with explicit drop counting, graceful shutdown drain.
- A hardened systemd unit (`packaging/systemd/ghostport.service`) running
  as a non-root user with a minimal, explicit capability set, plus install/
  uninstall/upgrade/rollback documentation (`docs/INSTALL.md`).
- A periodic `status` JSON event (uptime, kernel release, flow count against
  the BPF map's capacity, scan-detector and event-delivery internals), on
  by default and disableable with `--status=false`; and standard
  `sd_notify(3)` integration under systemd (`READY=1` only after a
  successful TCX attach, `WATCHDOG=1` pings when `WatchdogSec=` is
  configured), a no-op outside systemd.
- A threat model (`docs/THREAT_MODEL.md`) covering eBPF parsing, scan
  detection, event delivery, and service hardening.
- Multi-architecture (linux/amd64, linux/arm64) release packaging with
  SHA-256 checksums, driven by pushing a version tag.
- CI: reproducible eBPF compilation (verified byte-for-byte against a fresh
  build, with sanitized debug paths), unit tests, race detection, `go vet`,
  `staticcheck`, `govulncheck`, `gitleaks`, `shellcheck`, `actionlint`, and
  four real Linux/root integration tests: a loopback traffic smoke test, a
  synthetic port-scan detection test, privileged eBPF program tests run via
  `BPF_PROG_TEST_RUN` against well-formed/malformed/fragmented packets and
  map-eviction load, and a full systemd install/run/stop test.

### Changed

- `traffic_counts` moved from `BPF_MAP_TYPE_HASH` to `BPF_MAP_TYPE_LRU_HASH`
  so a burst of new flows evicts old entries instead of failing to record
  new ones once the map is full.
- Only the initial IPv4 fragment is parsed for a transport header; later
  fragments are counted by source/destination/protocol with destination
  port 0, instead of misreading fragment payload bytes as a TCP/UDP header.
- GitHub Actions pinned to commit SHAs instead of mutable version tags.

### Fixed

- The committed eBPF object no longer embeds the CI runner's filesystem
  checkout path in its DWARF debug information (`-fdebug-prefix-map`).

### Security

- Added a proactive kernel-version check (TCX requires Linux 6.6+) with a
  clear, actionable error instead of relying solely on the kernel's own
  attach-time failure.
- Documented (and pinned via unit tests) the existing byte-order assumption
  between the eBPF program and the Go userspace reader.
