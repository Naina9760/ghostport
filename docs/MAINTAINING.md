# Maintaining

These settings cannot be changed through a pull request. Turn them on in the
repository settings after creating it.

1. **Branch protection on `master`.** Settings, Branches: require a pull request
   and the `verify` check from CI before merging.
2. **Dependabot alerts and security updates.** Settings, Code security.
   `.github/dependabot.yml` already opens weekly update pull requests for Go
   modules and GitHub Actions; alerts are a separate switch.
3. **Private vulnerability reporting.** Settings, Code security. `SECURITY.md`
   relies on it.
4. **First release.** Run the Release workflow by hand (`workflow_dispatch`) to
   check that the packages build, then push a `v0.1.0` tag. The workflow builds
   the linux amd64 and arm64 packages, writes checksums and an SBOM, attests
   build provenance and publishes the GitHub Release.
