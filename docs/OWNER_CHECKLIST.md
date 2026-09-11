# Owner/admin checklist

Actions in this file require repository owner or admin permissions and cannot
be completed by a collaborator through a pull request. Each item states the
current measured state, why it matters, and the exact steps to resolve it.

## 1. Protect the `master` branch

**Measured state:** `gh api repos/Naina9760/ghostport/branches/master/protection`
returns `404 Not Found` (checked 2026-09-11) — no branch protection rule
exists yet.

**Why it matters:** Without protection, any collaborator with write access can
push directly to `master`, bypassing CI and review.

**Steps:**
1. Repository Settings → Branches → Add branch protection rule for `master`.
2. Require a pull request before merging.
3. Require the `CI` status check (`verify` job) to pass before merging.
4. Optionally require at least one approving review.
5. Consider also blocking force pushes and branch deletion.

## 2. Enable Dependabot alerts and private vulnerability reporting

**Measured state:** `gh api repos/Naina9760/ghostport/dependabot/alerts` returns
`403 Dependabot alerts are disabled for this repository` (checked 2026-09-11).
`.github/dependabot.yml` is already configured (weekly `gomod` and
`github-actions` update checks) but the repository-level feature is off.

**Why it matters:** Without this enabled, dependency vulnerabilities in
`cilium/ebpf`, `golang.org/x/*`, and pinned GitHub Actions will not surface
automatically, and there is no private channel for outside researchers to
report vulnerabilities (`SECURITY.md` already references this).

**Steps:**
1. Repository Settings → Security → Code security.
2. Enable "Dependabot alerts".
3. Enable "Dependabot security updates".
4. Enable "Private vulnerability reporting".

## 3. Decide on the historical `ghostport-controller` binary

**Measured state:** A 5,620,527-byte precompiled binary named
`ghostport-controller` exists in the initial commit `33aae92`, blob
`83485cf85cb45b13d40223158c0a8ac5b410d535`. It was removed from the working
tree in a later commit but remains reachable from every clone's Git history.

See `docs/HISTORICAL_BINARY_REPORT.md` for the full analysis. Purging it
requires rewriting and force-pushing history, which invalidates every
existing clone, fork, and open reference to current commit hashes. **Do not
purge without explicit confirmation from Satyawan**, per the task's Rule 9.

## 4. Confirm before the first `v0.1.0` tag and GitHub Release

Per the task rules, do not create the first public `v0.1.0` tag/release
without explicit confirmation from Satyawan, even once all implementation
phases pass CI. See the final report's release-readiness assessment.

## 5. Owner-authored license/legal review

Apache-2.0 was proposed in PR #10 and merged by `Naina9760` on
2026-09-11T17:58:10Z (`gh pr view 10 --json mergedBy` — measured), which
constitutes the required owner approval. No further action needed here
unless the owner wants outside legal review before a public release.
