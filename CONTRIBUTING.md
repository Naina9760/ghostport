# Contributing to GhostPort

Thank you for helping improve GhostPort.

## Before contributing

Contributions accepted into GhostPort are licensed under Apache-2.0. By
submitting a contribution, you confirm that you have the right to provide it
under that license.

For behavior changes, open or reference an issue that describes the threat model,
expected behavior, privacy impact, and verification plan. Keep pull requests
focused on one concern.

## Development checks

Run these checks before opening a pull request:

```sh
make fmt
make test
make vet
make build
```

Building the eBPF object requires Linux, Clang/LLVM, libbpf headers, and Linux
headers. Run the privileged smoke test on a compatible Linux system:

```sh
./scripts/integration-test.sh
```

CI repeats these checks and verifies release packaging. Do not commit generated
controller binaries. When changing the eBPF C source, commit the reproducibly
generated `cmd/ghostport/ghostport.bpf.o` with it.

## Pull requests

- Explain the user-visible and security impact.
- Add or update tests.
- Update documentation for flags, output, or requirements.
- Do not include secrets, packet captures, personal IP data, or unrelated files.
- Do not add commit trailers naming tools or assistants.

Maintainers may ask for changes before merging. Security-sensitive changes need
review from a repository owner.
