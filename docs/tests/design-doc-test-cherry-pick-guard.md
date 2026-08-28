# Design Doc: Test Cherry-pick Guard for sonic-net/sonic-mgmt

**Author:** xwjiang-ms  
**Status:** Reviewed  
**Reviewers:** Nightly Guard Team, Platform Owners  

---

## 1. Background & Motivation

The `sonic-net/sonic-mgmt` repository hosts the SONiC test framework used across all
SONiC platform releases. It maintains a `master` branch for active development and a set
of versioned **release branches** (e.g. `202205`, `202411`, `202505`) that correspond to
stable SONiC images shipped to partners and customers.

### Existing Cherry-pick Mechanism

A GitHub Actions workflow (`pr_cherrypick_prestep.yml`) already automates backporting:

1. A PR is merged to `master`.
2. A reviewer adds the label **`Approved for 202XXX branch`**.
3. The workflow automatically creates a cherry-pick PR targeting that release branch.
4. The cherry-pick PR receives an **`automerge`** label and merges without additional review.

### Problem

This automated pipeline has **no guardrail against backporting new test files**. When a
contributor adds a brand-new test to `master` and it gets approved for a release branch:

- The new test was written against `master`-era APIs, fixtures, and topology assumptions.
  It may fail or be incompatible on an older release branch.
- Nightly run failures on release branches erode confidence in those branches and increase
  on-call burden for the nightly guard team.
- There is currently **no audit trail** or awareness notification when this happens.
- The policy violation is discovered only after nightly failures, not at merge time.

### Goals

| Goal | Description |
|------|-------------|
| **Block** | Prevent new test files from being merged to non-master branches without review |
| **Tag** | Automatically label PRs that introduce new test files for visibility |
| **Bypass** | Allow authorized team members to override the block by adding a label |
| **Notify** | Alert the nightly guard team and platform owners whenever a bypass is granted |
| **Audit** | Preserve a permanent record of every bypass on the PR |

### Non-Goals

- Blocking modifications to *existing* test files (only *newly added* files are in scope)
- Enforcing code quality or test correctness
- Replacing the existing cherry-pick automation (this is additive)
- Blocking new tests merged to `master` (always allowed)

---

## 2. Terminology

| Term | Meaning |
|------|---------|
| **Release branch** | Any branch matching `20????` (e.g. `202411`) — a stable release snapshot |
| **New test file** | A file with `status: added` (not modified) matching test path patterns |
| **Bypass** | An authorized exception allowing a new test to merge to a release branch |
| **Policy check** | The GitHub Actions required status check enforcing this policy |
| **Guard team** | The team responsible for nightly test health across release branches |

---

## 3. Design

### 3.1 System Overview

```
┌──────────────────────────────────────────────────────────────────────┐
│                        GitHub Pull Request                           │
│  (direct PR to release branch  OR  auto-created cherry-pick PR)      │
└──────────────────────────────┬───────────────────────────────────────┘
                               │  opened / synchronize / labeled /
                               │  unlabeled
                               ▼
┌──────────────────────────────────────────────────────────────────────┐
│              GitHub Actions: test-cherry-pick-guard.yml               │
│              name: "Test Cherry-pick Guard"                          │
│                                                                      │
│  Job 1: detect-and-tag                                               │
│  ├─ Fetch PR file diff via GitHub API                                │
│  ├─ Match against test file patterns                                 │
│  ├─ Output: has_new_tests (bool), new_test_files (list), target_branch│
│  ├─ If new tests found → add label "contains-new-tests"              │
│  └─ If no new tests found → remove "contains-new-tests" label       │
│                                                                      │
│  Job 2: enforce-policy  (skipped if master or no new tests)          │
│  │  name: "Cherry-pick policy check"   ← branch protection matches  │
│  ├─ Check for "cherry-pick-bypass-approved" label                     │
│  ├─ Verify label adder is in @sonic-net/platform-owners (GitHub API) │
│  ├─ FAIL with guidance comment  (any condition unmet)                │
│  └─ PASS → send email (best-effort) + post audit comment             │
└──────────────────────────────────────────────────────────────────────┘
                               │
              (bypass approved + all conditions met)
                               │
                               ▼
              ┌────────────────────────────┐
              │  SMTP Email Notification   │
              │  (best-effort, non-gating) │
              │  To: Guard team + Owners   │
              │  Subject: [ACTION REQ'D]   │
              │  Body: PR, bypasser, files │
              └────────────────────────────┘
```

**Canonical names for branch protection:**

| YAML key | Value | Purpose |
|----------|-------|---------|
| Workflow `name:` | `Test Cherry-pick Guard` | Appears in Actions tab |
| Job 2 `jobs.enforce-policy.name:` | `Cherry-pick policy check` | **This is the string branch protection matches** |

### 3.2 Trigger Events

The workflow responds to the following GitHub event:

| Event | Types | Why |
|-------|-------|-----|
| `pull_request_target` | `opened`, `synchronize`, `reopened`, `labeled`, `unlabeled` | Covers PR creation, force-pushes, and label changes. Creates a check run on the PR HEAD SHA automatically. |

`pull_request_target` is used (instead of `pull_request`) because cherry-pick PRs are
created from a fork (`mssonicbld/sonic-mgmt`), which requires elevated token permissions.

> **Note:** If sonic-mgmt enables GitHub Merge Queues in the future, the workflow will
> need an additional `merge_group` trigger to prevent merges from bypassing the check.

### 3.3 Test File Detection

A file is classified as a **new test file** if:
- Its `status` in the PR diff is `"added"` (not `"modified"` or `"renamed"`)
- Its path matches any of the following patterns:

| Pattern | Framework | Example |
|---------|-----------|---------|
| `tests/**/test_*.py` | pytest (default) | `tests/bgp/test_bgp_fact.py` |
| `tests/**/*_test.py` | pytest (alternate) | `tests/bgp/bgp_fact_test.py` |

> **Note:** Both patterns are included because pytest's default discovery matches both
> `test_*.py` and `*_test.py`. Check `tests/pytest.ini` / `tests/conftest.py` for any
> non-default discovery configuration.

**Known limitation (v1) — renames:**
Cherry-picks may surface files as `"renamed"` rather than `"added"` depending on diff
similarity. Specifically:
- Cherry-picks created via `git cherry-pick` typically surface new files as `"added"`.
- Cherry-picks of a prior rename (or created via `git format-patch`) can surface as
  `"renamed"`, which v1 does not match.

A future iteration can also match `"renamed"` files whose new path matches test patterns
and whose previous path does not exist on the target branch.

### 3.4 Policy Enforcement State Machine

```
                    ┌───────────────────────────────┐
                    │  PR targets non-master branch  │
                    │  AND has new test files        │
                    └──────────────┬────────────────┘
                                   │
              ┌────────────────────┴──────────────────────┐
              │                                           │
    "cherry-pick-bypass-approved"              No bypass label present
         label present?
              │                                           │
             Yes                                    ❌ FAIL
              │                    Post: policy violation comment (once)
              │                    Marker: <!-- cherry-pick-guard-violation -->
    ┌─────────┴──────────┐
    │                    │
  Label adder        Label adder NOT in
  in authorized      authorized team
  org team?
    │                    │
   Yes                ❌ FAIL
    │               Post: unauthorized bypass comment
    │
✅ PASS
Send email notification (best-effort, once)
Post audit comment on PR
```

**Idempotent comments:** Both the policy violation comment and the bypass audit comment
use hidden HTML markers to ensure they are posted at most once per PR:
- Violation comment: `<!-- cherry-pick-guard-violation -->`
- Audit/notification comment: `<!-- cherry-pick-bypass-notification-sent -->`

Before posting, the workflow searches existing PR comments for the marker. If found,
the comment is not re-posted.

**Label cleanup on force-push:** On each `synchronize` event, Job 1 re-evaluates the
file diff. If `has_new_tests == false` (e.g., the contributor force-pushed to remove the
new test files), the workflow removes the `contains-new-tests` label and Job 2 is
skipped, allowing the PR to proceed without a bypass.

**Behavior on `unlabeled` of `cherry-pick-bypass-approved`:** If someone removes the
bypass label after a successful pass, the next workflow run reverts to FAIL, restoring
the merge block. This acts as a useful kill switch — reviewers can revoke a bypass at
any time by removing the label.

### 3.5 Bypass Authorization

Authorization is verified at **check runtime** using the GitHub API:

```
GET /orgs/{AUTH_ORG}/teams/{AUTH_TEAM}/memberships/{login}
→ 200 + { "state": "active" }  ← authorized
→ 404 or state != "active"     ← not authorized
```

Default values: `AUTH_ORG=sonic-net`, `AUTH_TEAM=sonic-mgmt-platform-owners`.
Both are configurable via GitHub repository variables without changing the workflow file.

> **Note:** The team membership API checks **direct membership only**. If
> `sonic-mgmt-platform-owners` adds child teams in the future, members of those child
> teams will NOT be authorized. This is intentional for v1 to keep the authorization
> model simple and auditable. If child team support is needed later, switch to the
> broader org permission check.

> **Note:** The team membership API (`GET /orgs/{org}/teams/{team}/memberships/{user}`)
> requires the **`read:org`** OAuth scope. The default `GITHUB_TOKEN` does not have this
> scope. The workflow uses a **GitHub App** installation token with Organization → Members
> → Read permission (see Section 6).
>
> **Decision (formerly Open Question #4):** GitHub App is chosen over PAT because:
> - PATs are tied to individual accounts and break when the user leaves the org
> - App tokens scope cleanly to the repository with auditable permissions
> - App tokens auto-rotate and don't require manual secret rotation

**Label adder identification:** The workflow identifies who added the bypass label by
querying the PR timeline API (`GET /repos/{owner}/{repo}/issues/{number}/timeline`) and
finding the most recent `labeled` event for the `cherry-pick-bypass-approved` label. This
approach works regardless of which event triggered the current workflow run.

> **Timeline API caveat:** The timeline endpoint has multi-second eventual-consistency
> lag. When the workflow is triggered by a `labeled` event, it should prefer
> `github.event.sender.login` (available immediately) over the timeline lookup. The
> timeline lookup is used as a fallback for non-`labeled` triggers (e.g., `synchronize`)
> where the sender is not the label adder. If the timeline lookup returns no matching
> event, the workflow retries once after a 5-second delay before failing.

### 3.6 Email Notification

Sent via SMTP (STARTTLS) using an inline workflow step.
Sent **once per PR** — a hidden HTML comment `<!-- cherry-pick-bypass-notification-sent -->`
is embedded in the audit comment and checked before each send to prevent duplicates on
workflow re-runs.

**Email is best-effort and non-gating.** If the SMTP send fails, the workflow logs the
error but does **not** fail the check. This prevents SMTP outages from blocking all
new-test cherry-picks across release branches. A missed email is an audit gap (the PR
comment audit trail still exists), not a merge gate.

> **Concurrency control:** To prevent a race condition where two concurrent workflow runs
> both see "marker not present" and both send the email, the workflow uses a
> [`concurrency` group](https://docs.github.com/en/actions/using-jobs/using-concurrency)
> keyed on the PR number:
>
> ```yaml
> concurrency:
>   group: cherry-pick-guard-${{ github.event.pull_request.number || github.event.issue.number }}
>   cancel-in-progress: false
> ```

**Email content:**

| Field | Value |
|-------|-------|
| Subject | `[sonic-mgmt][ACTION REQ'D] Cherry-pick Bypass — New Tests → <branch>` |
| To | `GUARD_NOTIFICATION_EMAIL` (comma-separated, set as secret) |
| Body | PR link, author, target branch, bypass approver, new file list |

### 3.7 Audit Trail

Every bypass creates a permanent record directly on the PR:

1. **`contains-new-tests` label** — visible in PR list views
2. **`cherry-pick-bypass-approved` label** — records that an exception was granted
3. **Audit comment by GitHub App bot** — posted by the GitHub App installation
   (appears as `<app-name>[bot]`), confirms notification was sent, records the approver

> **Future enhancement (v2):** An optional explanation comment requirement
> (`[cherry-pick-bypass-reason]`) can be added if the team wants written justification
> for each bypass. Keeping v1 label-only to validate the core workflow first.

---

## 4. Integration with Existing Cherry-pick System

```
  master PR merged
       │
       │  reviewer adds "Approved for 202411 branch"
       ▼
  pr_cherrypick_prestep.yml
       │  creates cherry-pick PR targeting 202411
       │  adds "automerge" label to new PR
       ▼
  NEW: test-cherry-pick-guard.yml runs on new cherry-pick PR
       │
       ├─ No new tests → ✅ automerge proceeds normally
       │
       └─ Has new tests → ❌ required check fails
                          automerge is BLOCKED
                          Platform owner must review and bypass
```

The guard is **additive and non-breaking** for PRs without new tests.

---

## 5. File Structure

```
sonic-net/sonic-mgmt/
├── .github/
│   ├── workflows/
│   │   └── test-cherry-pick-guard.yml     # Main workflow (Jobs 1 & 2)
│   └── scripts/
│       └── check_new_tests.py             # Standalone test-file detector (also used locally)
└── docs/
    └── tests/
        └── design-doc-test-cherry-pick-guard.md   # This design document
```

> **Note:** Email sending is handled inline in the workflow via an SMTP step rather than a
> separate script, to avoid duplicating logic and keep secrets management in one place.

---

## 6. Configuration Reference

### Token Permissions

The workflow uses a **GitHub App** installation token for operations requiring elevated
permissions. The default `GITHUB_TOKEN` is used for standard operations:

| Permission | Token source | Why |
|------------|-------------|-----|
| `pull-requests: write` | `GITHUB_TOKEN` | Post comments, add/remove labels |
| `contents: read` | `GITHUB_TOKEN` | Read PR file list |
| `read:org` | GitHub App token | Query team membership for bypass authorization |

### GitHub App Setup

Create a GitHub App with the following permissions and install it on the `sonic-net` org:

| Permission | Access | Why |
|------------|--------|-----|
| Organization → Members | Read | Query team membership for bypass authorization |
| Repository → Pull requests | Write | Post audit comments (optional — can use `GITHUB_TOKEN` instead) |

Store the App ID and private key as repository secrets (see below).

### GitHub Secrets (Settings → Secrets → Actions)

| Secret | Required | Example | Description |
|--------|----------|---------|-------------|
| `CHERRY_PICK_GUARD_APP_ID` | ✅ | `123456` | GitHub App ID |
| `CHERRY_PICK_GUARD_APP_PRIVATE_KEY` | ✅ | `-----BEGIN RSA...` | GitHub App private key (PEM) |
| `SMTP_SERVER` | ✅ | `smtp.office365.com` | SMTP relay hostname |
| `SMTP_PORT` | ✅ | `587` | Port (587 = STARTTLS) |
| `SMTP_USERNAME` | ✅ | `noreply@contoso.com` | SMTP login / sender |
| `SMTP_PASSWORD` | ✅ | `••••` | SMTP password or app password |
| `SMTP_FROM_EMAIL` | ✅ | `noreply@contoso.com` | From address |
| `GUARD_NOTIFICATION_EMAIL` | ✅ | `guard@contoso.com` | Comma-separated recipients |

### GitHub Variables (Settings → Variables → Actions)

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTH_ORG` | `sonic-net` | Org owning the authorized team |
| `AUTH_TEAM` | `sonic-mgmt-platform-owners` | Team slug for bypass authorizers |

### Branch Protection Rule

On Settings → Branches, for pattern `20????`:
- ✅ Require status checks: **`Cherry-pick policy check`** (must match Job 2's `name:` exactly)
- ✅ Do not allow bypassing the above settings

---

## 7. Security Considerations

| Risk | Mitigation |
|------|-----------|
| Unauthorized user adds bypass label | Workflow verifies label adder's org-team membership via GitHub API at runtime; fails even if label is present |
| Duplicate email spam on re-runs | Idempotent guard: checks for `<!-- cherry-pick-bypass-notification-sent -->` marker before sending; `concurrency` group prevents race conditions between parallel runs |
| `pull_request_target` privilege escalation | Workflow only reads PR metadata via API; no checkout of untrusted code |
| Token scope | `GITHUB_TOKEN` has minimal permissions; `read:org` is isolated to a GitHub App token with scoped permissions |
| SMTP outage | Email is best-effort; SMTP failure does not fail the check (see Section 3.6). The PR audit comment still provides a permanent record |

---

## 8. Rollout Plan

| Phase | Action | Verification |
|-------|--------|-------------|
| **Phase 1** | Commit workflow files to `master` | Workflow appears in Actions tab; no PRs blocked yet (no branch protection rule) |
| **Phase 2** | Set GitHub Secrets (SMTP + GitHub App keys) with your own email as `GUARD_NOTIFICATION_EMAIL` | Open a test PR to a release branch adding a `test_*.py` file; verify block + email to yourself |
| **Phase 3** | Add branch protection rule for `20????` requiring `Cherry-pick policy check` | Confirm the check status shows as failing (required) on the test PR before any bypass label is added |
| **Phase 4** | Verify bypass flow end-to-end | Have a `sonic-mgmt-platform-owners` member add bypass label on the test PR; verify pass + email |
| **Phase 5** | Update `GUARD_NOTIFICATION_EMAIL` to guard team DL + platform owners alias | Done |

---

## 9. Open Questions

| # | Question | Owner | Status |
|---|----------|-------|--------|
| 1 | ~~Which GitHub team slug?~~ Using `sonic-mgmt-platform-owners` as a concrete placeholder. Team to be created or re-pointed before Phase 4. | Platform team | **Resolved** |
| 2 | Do we need a weekly digest of all bypasses, or is per-bypass email sufficient? | Guard team | Open |
| 3 | Should the policy also apply to non-release feature branches (e.g. `feature/*`)? | Platform team | Open |
| 4 | ~~PAT vs GitHub App?~~ Resolved: GitHub App (see Section 3.5). | Platform team | **Resolved** |

---

## 10. Alternatives Considered

### A. Block at the labeling step (before cherry-pick PR is created)
Intercept `Approved for 202XXX branch` label on master PRs and refuse to create the
cherry-pick PR if it adds new tests.

**Rejected:** The existing cherry-pick workflow is not easily intercepted (it runs
`pull_request_target: labeled`) and cannot "block" a label being added. A required
status check on the cherry-pick PR itself is cleaner and more standard.

### B. Maintain an allowlist of approved files in a config YAML
Allow specific test files to be pre-approved for release branches.

**Rejected:** Adds maintenance overhead and doesn't enforce a real review — the bypass
label on the PR provides sufficient traceability for v1.

### C. Use a GitHub App instead of a GitHub Actions workflow
A GitHub App could react to label events in real time and have richer API access.

**Rejected:** Requires provisioning and maintaining a separate service. GitHub Actions
is already the established pattern in this repo and requires no new infrastructure.

### D. Use GitHub Environments with required reviewers
Mark the `release-branch` environment as requiring approval before deploy.

**Rejected:** Environments are designed for deployment workflows, not PR merge gates.
The label + comment pattern is more familiar to contributors already using the
`Approved for 20XXXX branch` label system.

### E. Require an explanation comment in addition to the bypass label
Require a `[cherry-pick-bypass-reason]` comment from an authorized team member before
the check passes.

**Deferred to v2:** Adds complexity (comment authorization, edit/delete handling,
`issue_comment` trigger + Checks API). Label-only bypass is simpler and sufficient
to validate the core blocking flow. Can be added later if the team wants written
justification for each bypass.

---

## 11. Observability

To track bypass frequency and detect potential policy abuse, the following observability
mechanisms are recommended:

- **Label-based query:** Use GitHub's search to list all PRs with the
  `cherry-pick-bypass-approved` label: `is:pr label:cherry-pick-bypass-approved`
- **Monthly audit:** Run a periodic query (e.g., Kusto or GitHub API script) against
  the audit comments (`<!-- cherry-pick-bypass-notification-sent -->`) to count bypasses
  per month, per branch, and per approver
- **Dashboard (future):** If bypass volume warrants it, build a lightweight dashboard
  showing bypass trends over time, top bypassed branches, and top approvers

This data will inform whether v2's explanation comment requirement is needed.
