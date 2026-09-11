# GhostPort

GhostPort is a lightweight Linux network sensor. It attaches an eBPF traffic
classifier to a network interface and reports IPv4 packet counts grouped by
source address.

This repository currently targets the first production milestone: a reliable
single-host sensor with text and newline-delimited JSON output. Scan detection,
decoy services, fleet coordination, alert delivery, and a dashboard are planned
separately; the current sensor should not yet be described as a complete
honey-mesh.

## Requirements

- Linux kernel 6.6 or newer with BPF and TCX support
- Root or the capabilities required to load and attach BPF programs
- Go 1.25 or newer
- Clang/LLVM with the BPF target
- Linux and libbpf development headers

On Ubuntu or Debian, install the native build dependencies with:

```sh
sudo apt-get update
sudo apt-get install -y clang llvm libbpf-dev linux-libc-dev
```

## Build

```sh
make build
```

The resulting executable is `bin/ghostport`. The build recompiles the eBPF
object from `cmd/ghostport/ghostport.bpf.c` before building the Go controller.

## Run

List available interfaces and start the sensor on one of them:

```sh
ip link show
sudo ./bin/ghostport --interface eth0
```

Change the reporting interval or produce machine-readable output:

```sh
sudo ./bin/ghostport --interface eth0 --interval 10s --json
```

Stop the process with `Ctrl+C` or `SIGTERM`. GhostPort detaches the TCX link
before exiting.

## Development

```sh
make fmt
make test
make vet
```

On a compatible Linux host, `scripts/integration-test.sh` attaches the built
sensor to the loopback interface, generates traffic, and confirms that GhostPort
reports it. The script requires `sudo` and is also run by CI.

The checked-in `cmd/ghostport/ghostport.bpf.o` is embedded into the controller.
After editing the C source, run `make bpf` on Linux and commit the regenerated
object with the source change. CI verifies that the object is reproducible.

## Current scope

GhostPort v1 observes IPv4 ingress traffic and reports cumulative counts. It
does not block, redirect, or modify traffic. It does not inspect payloads.

Planned follow-up milestones:

1. TCP/UDP port and scan-pattern telemetry.
2. Configurable alert thresholds and structured event delivery.
3. Decoy-service orchestration.
4. Authenticated fleet management and a central dashboard.

## Security and privacy

Running eBPF software changes kernel state and requires elevated privileges.
Build the executable from reviewed source, use it first in a test environment,
and restrict telemetry access. Source IP addresses may be personal data under
applicable privacy law.

## License

No license has been selected yet. The repository owner should choose and add one
before external distribution or reuse.
