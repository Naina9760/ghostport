# Contributing to GhostPort

Thank you for helping improve GhostPort.

## Before contributing

The repository owner must add an open-source license before external
contributions can be accepted. Until that happens, use issues for discussion and
do not submit substantial third-party code.

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
