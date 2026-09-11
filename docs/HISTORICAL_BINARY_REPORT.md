# Historical `ghostport-controller` binary: findings and purge analysis

## What is in the history

**Measured** via `git rev-list --objects --all | git cat-file --batch-check`:

- Path: `ghostport-controller`
- Blob ID: `83485cf85cb45b13d40223158c0a8ac5b410d535`
- Size: 5,620,527 bytes
- Introduced in: initial commit `33aae92` ("Initial commit: GhostPort eBPF
  honey-mesh sensor and controller")
- Not present in the current working tree (`git ls-tree -rl HEAD` at commit
  `b60a14f` does not list it) — it was removed in a later commit, but the
  blob remains reachable from the initial commit, which every branch and tag
  still descends from.

The file was not inspected for contents beyond size and blob ID, since
extracting and analyzing an unknown precompiled binary carries its own risk;
if the owner wants its provenance understood (what it was built from, what
it linked against), that would need a separate, deliberate review.

## Why it is a hygiene concern

- It roughly doubles the size of every fresh clone (5.6 MB against a repo
  whose current tree is under 1.2 MB, the bulk of which is the hero image).
- A precompiled, unreviewed binary sitting in history is exactly the kind of
  artifact a security-conscious downstream user or auditor will flag, even
  though it is inert (git history, not the working tree) and cannot execute
  on its own.
- It is not a secret or credential — `gitleaks detect --source . --log-opts="--all"`
  found no leaks in the same history — so it is a hygiene and size concern,
  not a confidentiality incident.

## What purging it actually requires

Git does not support deleting a single historical blob in place. The only
ways to remove it are history-rewriting operations:

- `git filter-repo` (or the older `git filter-branch` / BFG Repo-Cleaner) to
  strip the blob from every commit that references it, rewriting all commit
  hashes from `33aae92` forward.
- A force-push of the rewritten `master` (and any other affected refs) to
  replace the current history on GitHub.

## Exact consequences of doing this

1. **Every commit hash changes**, starting from `33aae92`. All 6 current
   commits on `master`, and their merge commits (`2148741`, `d114c38`,
   `f91fa04`, `dc37e0e`, `31ecdfb`, `b60a14f`), get new hashes.
2. **Every existing clone or fork becomes divergent.** Anyone who has already
   cloned the repository (including any local clone Satyawan or Naina9760
   already has outside this session) will see a forced/non-fast-forward
   history on their next `git fetch` and must manually reset to the new
   history or re-clone. Any fork on GitHub keeps the old history until its
   owner manually rebases.
3. **All merged pull request references** (`#1`, `#2`, `#8`, `#9`, `#10`,
   `#11`) keep their PR numbers and descriptions on GitHub, but the commit
   SHAs shown in them, in CI run logs, and in any external link that cites a
   specific commit hash (issue comments, chat messages, this very
   conversation) become stale — the hashes cited above by this report would
   no longer resolve to the same content in a rewritten history.
4. **CI history is disconnected.** Existing GitHub Actions run records stay
   linked to the old commit SHAs; new runs after the rewrite start a fresh
   chain.
5. **Recovery is possible but manual.** GitHub retains unreferenced commits
   for a period after a force-push (subject to its reflog/garbage-collection
   window), and anyone holding a pre-rewrite clone can restore the original
   history from their local `.git` — but there is no automatic undo once the
   force-push lands and clones diverge.

## Recommendation

Given the repository is small, pre-`v0.1.0`, and has not yet had its first
public tag or release, this is close to the cheapest point in the project's
life to do a history rewrite if the owner wants the binary gone — later,
after `v0.1.0` ships and external forks/clones multiply, the cost only grows.

That said, this is explicitly an action the task rules gate on Satyawan's
confirmation (Rule 9: no force-push or history rewrite without explicit
confirmation, with impact explained first — which this document is intended
to satisfy). No rewrite has been performed. If confirmed, the recommended
sequence is:

1. Confirm both Satyawan and repository owner `Naina9760` are aware (a
   force-push to `master` affects `Naina9760`'s repository, not just a
   collaborator branch).
2. Ask any other clone holders to push or stash outstanding work first.
3. Run `git filter-repo --path ghostport-controller --invert-paths` on a
   fresh mirror clone.
4. Force-push the rewritten `master` (and any tags, though none exist yet).
5. Have all collaborators re-clone rather than reconcile their existing
   clones.

If the owner instead prefers to leave it, the practical cost of doing nothing
is a ~5.6 MB permanent addition to clone size and one line in a security
audit — not a functional or confidentiality risk.
