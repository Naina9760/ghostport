# GhostPort roadmap

## v0.1: single-host sensor

- [x] Attach an ingress eBPF program to a selected interface.
- [x] Report cumulative IPv4 traffic by source address.
- [x] Support text and newline-delimited JSON output.
- [x] Test real attachment and traffic capture on Linux CI.
- [x] Produce versioned AMD64 and ARM64 release packages.
- [x] Obtain repository owner approval for the proposed Apache-2.0 license.
- [ ] Protect the default branch and require CI.

## v0.2: detection

- [x] Count TCP and UDP traffic by source address and destination port.
- [x] Detect horizontal and vertical port-scan patterns.
- [x] Add configurable thresholds and suppression windows.
- [x] Emit versioned structured events without packet payloads.
- [x] Add integration fixtures for benign and scan traffic.

## v0.3: delivery and operations

- [x] Deliver events to a configurable HTTPS endpoint.
- [x] Authenticate events and retry with bounded backoff.
- [ ] Add health and sensor-status reporting.
- [ ] Package a hardened systemd service.
- [ ] Document upgrades and rollback.

## Later: honey-mesh

- [ ] Define the threat model and decoy-service policy.
- [ ] Coordinate authorized decoy services across multiple hosts.
- [ ] Build an authenticated fleet inventory and event dashboard.
- [ ] Add retention, privacy, and incident-response controls.
