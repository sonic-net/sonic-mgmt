# Pre-flight static analysis

A fast static-analysis gate that runs on every pull request and, critically, on
`merge_group` events so it can gate a GitHub merge queue.

## Why a merge queue check

A pull request is tested against the branch as it looked when the branch was
cut. Two pull requests can each be green and still break master when combined —
one renames a helper, the other adds a caller. Nothing in the current CI catches
that, because nothing runs against the merged result. A merge queue does exactly
that, and this check is what runs there.

## The one rule

**A finding is reported only if it lands on a line the change added or
modified.** Pre-existing problems elsewhere in a touched file are dropped.

This is not a nicety, it is what makes the check adoptable. Measured on this
repository, pyright reports 928 pre-existing errors across the files touched by
14 recent commits. Only 10 of those sit on lines those commits actually changed.
Without the filter, every pull request would fail on day one and the check would
be turned off within a week.

One consequence worth knowing: a moved or reindented line counts as changed, so
a long-standing problem on a line your change shifts can surface. This is
inherent to line-based filtering and matches how `darker` and `diff-cover`
behave.

`test_preflight.py` exists to protect this rule, and runs in CI ahead of the
analysis itself.

## What runs

| Tool | Blocking | Notes |
| --- | --- | --- |
| flake8 | yes | Mirrors `.pre-commit-config.yaml` exactly, including the per-directory ignore lists, so this check can never disagree with local `pre-commit` |
| pyright | yes | None-safety, possibly-unbound names, calls that do not match the signature |
| yamllint | no | advisory |
| shellcheck | no | advisory |
| ansible-lint | no | advisory |
| codespell | no | advisory |

Measured on 14 recent PR-sized commits: flake8 blocked 0, pyright blocked 1. The
one pyright hit was a real defect — a possibly-unbound `src_duthost`, five
`None` subscripts, and a call passing a keyword argument the callee does not
accept.

The advisory tools have no measured baseline on this repository, so they
annotate but never fail. Promoting one is a single `blocking: true` edit in
`config.yml`.

### pyright configuration

`reportMissingImports` is off because the test dependencies are not installed in
this job; without that, every file reports unresolved imports and the real
findings are buried. Installing them would add minutes to a check that gates the
queue.

Two settings are load-bearing and easy to get wrong:

- `typeCheckingMode` is `standard`, not `basic`. Measured on a real change,
  `basic` silently drops `reportPossiblyUnboundVariable` and `reportCallIssue`.
- `reportGeneralTypeIssues` is deliberately **not** disabled. It is a catch-all
  that also suppresses `reportCallIssue` and `reportOperatorIssue`; disabling it
  took 12 findings down to 10 on one real change.

pyright silently ignores unknown configuration keys, so a misspelled rule name
disables a check with no warning. `test_preflight.py` asserts the exact spelling
of the rule most likely to be typo'd.

**pyright's results depend on the Python environment it finds.** It infers
imports from whichever interpreter is on `PATH`, so installed packages change
type inference and therefore the findings. The same commit produced 46 errors
under a bare interpreter and 37 when `pytest` happened to be installed. CI is
reproducible because the runner is fresh and every tool version is pinned, but
a local run will not always match CI. If you are reproducing a CI result, use a
clean virtualenv containing only the packages the workflow installs.

## Azure Pipelines and the merge queue

The Azure pipelines that spawn real testbed runs **do not** trigger on merge
groups, and no change was needed to keep it that way:

- `azure-pipelines.yml` sets `trigger: none`, so nothing runs on branch pushes.
  A merge queue works by pushing to `gh-readonly-queue/**` refs, which that
  setting already excludes.
- Its only trigger is `pr:`, which fires on GitHub `pull_request` events. A
  merge group is not a pull request and emits no such event.

**This must be re-checked if `trigger:` is ever given a branch list.** Adding
`gh-readonly-queue/**` there, directly or via a wildcard, would spawn a full
testbed run for every queue entry.

## Enabling the merge queue

The workflow is ready for it, but turning the queue on is a repository settings
change, not a file in this repository. Note one sharp edge before doing it:

> When a merge queue is enabled, required status checks are evaluated against
> the **merge group**, not the pull request. Any required check that does not
> run on `merge_group` will never report, and pull requests will sit in the
> queue until they time out.

Today `Azure.sonic-mgmt`, `Semgrep`, and `CodeQL` all trigger on
`pull_request` only. Making the queue work therefore means deciding, per check,
either to add a `merge_group` trigger or to drop it from the required list.
Recommendations based on measured cost:

- **Semgrep** (~33s, and already diff-aware via its own baseline scan) — cheap
  enough to add to the queue.
- **CodeQL** (~7m20s) — too slow to gate a queue. Keep it on pull requests.
- **Azure.sonic-mgmt** — must stay out of the queue; that is the entire point.

## Running it locally

```bash
pip install flake8 pyright yamllint ansible-lint codespell PyYAML
PREFLIGHT_BASE=origin/master PREFLIGHT_HEAD=HEAD python .github/preflight/run_preflight.py
```

Tools that are not installed are skipped with a warning rather than failing the
run, so you can check just the ones you have.

To run the tests for the filter itself:

```bash
python .github/preflight/test_preflight.py
```
