# GhostPort threat model

This describes what GhostPort protects, what it assumes, what it does not
defend against, and what happens when each part of it fails. It reflects
the code as implemented, not aspirational scope; update it in the same pull
request as any change to the behavior it describes.

## What GhostPort is

A single-host Linux sensor. It attaches an eBPF program to one network
interface's TCX ingress hook, counts IPv4 traffic by source, destination,
protocol, and destination port, detects vertical and horizontal port-scan
patterns in that traffic, and can optionally deliver alerts about those
patterns to an operator-configured HTTPS endpoint.

## What GhostPort is not

- Not a firewall or IPS: it never drops, redirects, or modifies traffic.
  Its eBPF program always returns `TC_ACT_OK`.
- Not a full IDS: it looks at IPv4 headers only. It does not inspect
  payloads, does not decode application protocols, and does not detect
  anything other than the two scan shapes described in the README.
- Not a fleet or multi-host system (yet): each instance is independent,
  with no coordination, shared state, or central control plane.
- Not a decoy/honeypot system (yet): "honey-mesh" in the project's name
  describes a planned future milestone, not current behavior.

## Assets

- **Confidentiality of observed traffic metadata**: source/destination IP,
  protocol, destination port, and packet counts. Source IP addresses may be
  personal data under some privacy regimes (GDPR and similar). No packet
  payload is ever read, stored, or transmitted.
- **Integrity of the host's network stack**: GhostPort runs privileged
  kernel code. A bug in the eBPF program is a kernel-level failure, not a
  process crash.
- **Availability of the monitored network path**: a hung or slow eBPF
  program on the ingress hook can affect real traffic on that interface.
- **Confidentiality of the delivery credential**: `GHOSTPORT_DELIVERY_TOKEN`,
  when event delivery is enabled.

## Trust boundaries

1. **Kernel ↔ eBPF program**: enforced by the kernel's BPF verifier at load
   time, not by GhostPort. GhostPort cannot make an unsafe program safe;
   see [eBPF parsing](#ebpf-parsing).
2. **Network ↔ GhostPort**: every byte the eBPF program reads comes from
   the wire (or loopback). It is untrusted input.
3. **Operator ↔ GhostPort**: CLI flags and the `GHOSTPORT_DELIVERY_TOKEN`
   environment variable are trusted (whoever can set them can already
   control what GhostPort does).
4. **GhostPort ↔ delivery endpoint**: the endpoint is a separate trust
   domain, reached over the network. See
   [Event delivery](#event-delivery).

## eBPF parsing

The ingress program (`cmd/ghostport/ghostport.bpf.c`) parses attacker-
controlled bytes directly. Its safety model:

- **Memory safety** is enforced by the kernel verifier, not by the C code's
  own correctness: every header access is preceded by an explicit
  `data_end` bounds check, and the verifier rejects the program at load
  time if it can prove any access could go out of bounds. A bug here fails
  closed (load failure, GhostPort exits with an error) rather than
  unsafely.
- **Malformed or truncated packets** (an Ethernet frame with no IP header,
  a truncated IP header, a truncated TCP/UDP header) are recognized by the
  same bounds checks and simply not counted; they are not treated as an
  error. See `TestBPFProgramHandlesTruncated*` in `bpf_program_test.go`.
- **IPv4 options** are handled via `iph->ihl`, not assumed to be absent.
- **Fragmentation**: only the initial fragment (offset 0) is parsed for a
  transport header; later fragments are counted by source/destination/
  protocol only, with destination port 0. See `TestBPFProgramSkipsPortFor-
  NonInitialFragment`. GhostPort does not reassemble fragments, so a scan
  or exfiltration attempt that relies on payload split across fragments in
  a way that hides the real destination port from the first fragment is
  not fully visible to port-based detection.
- **IPv6 is entirely out of scope**: the program only matches EtherType
  0x0800 (IPv4). An IPv6-only or dual-stack attacker path is invisible to
  GhostPort as currently implemented. This is a real detection gap, not a
  crash risk.
- **Map exhaustion**: `traffic_counts` is `BPF_MAP_TYPE_LRU_HASH`, capped
  at 4096 entries. A flood of distinct flows evicts the least-recently-used
  entry rather than failing inserts or growing unbounded, but this means an
  attacker who can generate enough distinct flows can push a specific
  flow's counter out of the map, resetting it to 1 on its next packet. The
  scan detector treats a counter decrease as a fresh touch rather than a
  negative delta specifically because of this.
- **Concurrent updates**: two CPUs racing to insert the same brand-new flow
  key can lose one increment (a bounded, self-correcting undercount, not a
  crash or corruption). Documented in the map's comment in
  `ghostport.bpf.c`; not fixed with a per-CPU map, which would add real
  complexity for a marginal edge case at this scale.

## Scan detection

Operates entirely on already-aggregated `trafficRecord` data (never packet
payloads). Its correctness depends on the eBPF map behavior above, so it
inherits the same fragmentation and eviction caveats: a slow scan spread
past `--scan-window`, or a burst of unrelated traffic that evicts a
scanner's own entries from the 4096-entry map before the scanner reaches a
threshold, can under-count or miss detection.

Known false-positive sources (see also the README): NAT gateways, forward
proxies, and load balancers that legitimately touch many hosts or ports
from one address. GhostPort has no allowlist mechanism for this yet;
operators must tune `--scan-vertical-threshold` /
`--scan-horizontal-threshold` / `--scan-window` / `--scan-cooldown` for
their environment, or filter such sources upstream.

Detector state (per-source port/host sets, last-alert times) is in-memory
only and bounded by `--deliver-queue-size`-independent `MaxTrackedSources`
(4096, matching the BPF map's own cap) with least-recently-active eviction.
It does not persist across a restart: a restart loses in-progress scan
tracking, which could let a scan that straddles a restart go undetected.

## Event delivery

Disabled by default; enabling it adds a new trust boundary (the delivery
endpoint) and a new secret (`GHOSTPORT_DELIVERY_TOKEN`).

- The token is read from the environment only, never a CLI flag, and never
  logged.
- The endpoint must be `https://`; the HTTP client performs ordinary TLS
  certificate validation with no override, so a misconfigured or malicious
  endpoint with an invalid certificate is refused, not silently trusted.
- A compromised or malicious delivery endpoint can see every scan alert
  GhostPort generates (source/destination/port/protocol/counts) but cannot
  inject anything back into GhostPort: delivery is one-directional
  (GhostPort only sends; it does not act on the response body).
- A slow or unresponsive endpoint cannot block the sensor's reporting loop
  (delivery is queued and bounded) but can cause alerts to be dropped once
  the queue is full; drops are counted and logged, not silent.
- GhostPort trusts whatever `GHOSTPORT_DELIVERY_TOKEN` and
  `--deliver-endpoint` it is given; it does not validate that the endpoint
  is the one the operator intended beyond normal TLS/hostname verification.
  DNS or routing compromise that redirects the configured hostname to an
  attacker-controlled host with a validly-issued certificate for that
  hostname is out of scope for GhostPort itself.

## Running as a service

See `docs/INSTALL.md` for the full rationale. In short: GhostPort runs as a
dedicated non-root user with only the specific capabilities it needs
(`CAP_BPF`, `CAP_NET_ADMIN`, `CAP_PERFMON`, `CAP_SYS_RESOURCE`) rather than
root, inside a systemd sandbox that denies filesystem writes, namespace
changes, and most syscalls outside `@system-service` + `bpf`. A local
attacker who compromises the GhostPort process itself (e.g. via a Go
runtime or dependency vulnerability) inherits only those capabilities and
that sandbox, not full root.

Under systemd, GhostPort writes one-way `sd_notify(3)` messages
(`READY=1`, `WATCHDOG=1`, `STOPPING=1`) to the unix datagram socket named
by `$NOTIFY_SOCKET`, which systemd sets up per-unit specifically for this
purpose; GhostPort never reads from it. Outside systemd this environment
variable is unset and the code path is a no-op.

## Health and status reporting

The periodic `status` event (uptime, kernel release, flow count, detector/
delivery internals) is local-only: it is written to the same stdout stream
as traffic and scan-alert events and is never sent to the HTTPS delivery
endpoint. It reveals nothing about observed network traffic beyond an
aggregate count, so it does not expand the confidentiality concerns already
covered above.

## Explicitly out of scope

- Payload inspection of any kind.
- Detecting anything other than vertical/horizontal TCP/UDP port scans.
- IPv6.
- Reassembling fragmented IP datagrams.
- Multi-host coordination, decoy services, and a central dashboard (planned
  milestones, not implemented).
- Defending against an adversary who already has root or `CAP_BPF` on the
  monitored host: such an adversary can unload, replace, or blind
  GhostPort's own eBPF program.
