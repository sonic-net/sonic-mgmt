# GitHub Merge Queue

GitHub Merge Queue is a branch protection feature that validates pull requests
against the changes that will actually reach the target branch. When it is
enabled, approved pull requests enter a queue instead of merging directly.

This document describes merge queue behavior, the CI changes required by
SONiC, operational considerations, and a recommended initial configuration.
Validation results from the `sonic-mgmt` evaluation are included in the
appendix.

## 1. How merge queue works

GitHub creates a temporary merge group containing the latest target branch,
the pull request being validated, and compatible pull requests ahead of it.
The merge group must pass the required checks before its changes can merge.

### 1.1 Queue ordering and validation

- Each pull request is validated against the current target branch and the
  pull requests ahead of it.
- This prevents independently successful but mutually incompatible changes
  from breaking the target branch.
- Compatible pull requests can be validated and merged as one merge group.
- The configured build concurrency controls how many merge queue validation
  builds can run at the same time.

### 1.2 Failure, removal, and revalidation

When a queued pull request fails or is removed, GitHub rebuilds the affected
merge groups without that change. Pull requests behind it must then be
revalidated.

Removing a pull request that has not started validation has no special effect.
Removing one under validation triggers new CI runs for affected later pull
requests and increases their queue-to-merge time.

Queue status on the pull request page may temporarily lag behind failed checks
while GitHub processes earlier entries and recalculates the queue.

### 1.3 Jumping the queue

GitHub allows an urgent pull request to move ahead of other queued pull
requests. This can reduce latency for the urgent change, but every affected
pull request behind it must be revalidated.

### 1.4 Merge conflicts

If a pull request conflicts with another pull request ahead of it, GitHub
cannot create a temporary merge group branch containing both changes.

The merge queue page reports the conflict, but the pull request page may
continue to show **Queued to merge** until GitHub updates its state. Pull
requests behind the conflicting entry are not necessarily blocked: GitHub can
validate them using a merge group that excludes the conflicting change.

### 1.5 Squash merge behavior

Squash merge works with merge queue. GitHub uses the pull request title as the
squash commit message and does not provide an opportunity to edit it during
the queued merge.

## 2. Recommended initial configuration

For the current volume of approximately 1 to 20 merged pull requests per day,
start with the following settings:

| Setting | Initial value | Rationale |
| --- | --- | --- |
| Merge method | Squash | Preserves the repository's squash workflow. |
| Build concurrency | 5 | Balances queue latency with available CI capacity. |
| Minimum pull requests to merge | 1, or after 5 minutes | Avoids unnecessary waiting while still allowing grouped merges. |
| Maximum pull requests to merge | 5 | Larger groups improve throughput but increase the impact of failures. |

Review these values using production queue length, validation duration,
failure rate, and agent utilization data.

## 3. CI requirements

For merge queue validation, GitHub creates a temporary branch instead of
running checks directly on the target branch:

```text
refs/heads/gh-readonly-queue/<target-branch>/pr-<number>-<sha>
```
To make our CI support pre-test-only merge queue validation, we need to add a condition for the test stage.
If the source branch starts with `refs/heads/gh-readonly-queue`, then the test stage should be skipped.


## Appendix A: Validation results

### A.1 Environment

| Field | Details |
| --- | --- |
| Repository | `sonic-mgmt` |
| Test branch | `merge-queue-test` |
| Tested build concurrency | 5 |

### A.2 Test cases

The evaluation used pull requests designed to test queue ordering, concurrent
validation, dependent changes, failures, automatic revalidation, removal,
merge conflicts, squash merge, and grouped merges.

| Pull request | Change or purpose |
| --- | --- |
| PR1 | Removes the `time` package required by PR3. |
| PR2 | Contains two commits to test squash merge behavior. |
| PR3 | Requires the `time` package removed by PR1. |
| PR4 | Independent compatible change. |
| PR5 | Independent compatible change. |
| PR6 | Independent trailing change. |
| PR7 | Independent trailing change. |
| PR8 | Independent trailing change. |
| PR10 | Conflicts with PR11. |
| PR11 | Conflicts with PR10. |

All pull requests passed the normal PR checker before entering the merge queue.

### A.3 Dependency handling

| Time | Event | Outcome |
| --- | --- | --- |
| 11:19 a.m. | PR1 entered the queue. | PR1 became the first pull request in the queue. |
| 12:56 p.m. | PR3 entered the queue. | Validation started immediately because capacity was available. GitHub tested PR3 against the target branch, PR1, and PR3. |
| 1:00 p.m. | PR3 validation failed during static analysis. | Validation reported that `time` was undefined because PR1 removed a dependency PR3 still required. |
| 3:11 p.m. | PR1 failed during `prepare-testbed` and left the queue. | Checkout logic incorrectly shortened the temporary merge queue branch to a nonexistent `pr-<number>-<sha>` branch. |
| 3:12 p.m. | GitHub automatically revalidated PR3. | The new validation excluded PR1, so the missing `time` error disappeared. |

### A.4 Full queue run

|Event | Outcome |
| --- | --- |
|PR1 entered the queue. | PR1 began merge queue validation. |
| PR2 entered the queue. | The queue contained the target branch, PR1, and PR2. |
| PR4, PR5, and PR3 entered the queue. | Five pull requests were available for concurrent validation. |
| PR3 failed because the `time` package was missing. | PR3 temporarily remained queued while earlier entries were processed. |
| PR6 entered the queue. | Validation started immediately because capacity was available. |
| PR7 entered the queue. | Validation waited because the concurrency limit had been reached. |
| PR8 entered the queue. | PR8 waited behind the earlier pull requests. |
| PR1 merged. | The first pull request completed successfully. |
| PR2 left after a flaky test failure. | GitHub restarted validation for affected pull requests behind PR2. |
| PR4 merged. | PR4 completed revalidation successfully. |
| PR5 merged and PR3 left the queue. | PR3 remained incompatible with the now-merged PR1. Later validations restarted without PR3. |
| PR7 completed validation. | PR6 and PR7 merged in the same merge group. |
| PR8 merged. | The queue run completed. |
| PR2 re-entered the queue. | A new validation run started. |
| PR2 merged. | GitHub squash merged its two commits using the PR title as the commit message. |
