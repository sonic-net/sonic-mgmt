# Design Doc: Test Cherry-pick Guard for sonic-net/sonic-mgmt

**Author:** (your alias)  
**Status:** Draft  
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
| **Bypass** | Allow authorized team members to override the block with justification |
| **Notify** | Alert the nightly guard team and platform owners whenever a bypass is granted |
| **Audit** | Preserve a permanent record of every bypass and its explanation on the PR |

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
                               │  unlabeled / issue_comment:created
                               ▼
┌──────────────────────────────────────────────────────────────────────┐
│              GitHub Actions: test-cherry-pick-guard.yml               │
│                                                                      │
│  Job 1: detect-and-tag                                               │
│  ├─ Fetch PR file diff via GitHub API                                │
│  ├─ Match against test file patterns                                 │
│  ├─ Output: has_new_tests, new_test_files, target_branch             │
│  └─ If new tests found → add label "contains-new-tests"              │
│                                                                      │
│  Job 2: enforce-policy  (skipped if master or no new tests)          │
│  ├─ Check for "cherry-pick-bypass-approved" label                     │
│  ├─ Verify label adder is in @sonic-net/platform-owners (GitHub API) │
│  ├─ Check for [cherry-pick-bypass-reason] comment                     │
│  ├─ FAIL with guidance comment  (any condition unmet)                │
│  └─ PASS → send email + post audit comment  (all conditions met)     │
└──────────────────────────────────────────────────────────────────────┘
                               │
              (bypass approved + all conditions met)
                               │
                               ▼
              ┌────────────────────────────┐
              │  SMTP Email Notification   │
              │  To: Guard team + Owners   │
              │  Subject: [AWARENESS]...   │
              │  Body: PR, bypasser,       │
              │        explanation, files  │
              └────────────────────────────┘
```

### 3.2 Trigger Events

The workflow responds to two GitHub event types:

| Event | Types | Why |
|-------|-------|-----|
| `pull_request_target` | `opened`, `synchronize`, `reopened`, `labeled`, `unlabeled` | Covers PR creation, force-pushes, and label changes |
| `issue_comment` | `created` | Re-evaluates policy when an explanation comment is added |

`pull_request_target` is used (instead of `pull_request`) because cherry-pick PRs are
created from a fork (`mssonicbld/sonic-mgmt`), which requires elevated token permissions.

### 3.3 Test File Detection

A file is classified as a **new test file** if:
- Its `status` in the PR diff is `"added"` (not `"modified"` or `"renamed"`)
- Its path matches one of the following patterns:

| Pattern | Framework | Example |
|---------|-----------|---------|
| `tests/**/test_*.py` | pytest (primary) | `tests/bgp/test_bgp_fact.py` |
| `tests/**/conftest.py` | pytest fixtures | `tests/bgp/conftest.py` |
| `spytest/tests/**/*.py` | SpyTest | `spytest/tests/routing/test_ospf.py` |
| `sdn_tests/**/*_test.go` | Bazel / Ondatra | `sdn_tests/pins_ondatra/bgp_test.go` |

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
              │                              Post: policy violation comment
              │                              (once, idempotent)
    ┌─────────┴──────────┐
    │                    │
  Label adder        Label adder NOT in
  in authorized      authorized team
  org team?
    │                    │
   Yes                ❌ FAIL
    │               Post: unauthorized bypass comment
    │
  ┌─┴──────────────────────┐
  │                        │
[cherry-pick-bypass-reason]  No explanation
comment present?            comment
  │                        │
 Yes                     ❌ FAIL
  │                   Post: explanation required comment
  │
✅ PASS
Send email notification (once)
Post audit comment on PR
```

### 3.5 Bypass Authorization

Authorization is verified at **check runtime** using the GitHub API:

```
GET /orgs/{AUTH_ORG}/teams/{AUTH_TEAM}/memberships/{label_adder_login}
→ 200 + { "state": "active" }  ← authorized
→ 404 or state != "active"     ← not authorized
```

Default values: `AUTH_ORG=sonic-net`, `AUTH_TEAM=platform-owners`.  
Both are configurable via GitHub repository variables without changing the workflow file.

### 3.6 Explanation Comment Format

The explanation must be posted as a PR comment containing the marker
`[cherry-pick-bypass-reason]` (case-insensitive). Enforced format:

```
[cherry-pick-bypass-reason]
Reason:  <Why this test is needed on the release branch>
Impact:  <What breaks without this backport>
Owner:   <Alias — you own any fallout from this cherry-pick>
```

The workflow detects the most recent such comment, extracts the author and body,
and includes both in the notification email and the audit comment.

### 3.7 Email Notification

Implemented via `dawidd6/action-send-mail@v3` (SMTP/STARTTLS).  
Sent **once per PR** — a hidden HTML comment `<!-- cherry-pick-bypass-notification-sent -->`
is embedded in the audit comment and checked before each send to prevent duplicates on
workflow re-runs.

**Email content:**

| Field | Value |
|-------|-------|
| Subject | `[sonic-mgmt][AWARENESS] Cherry-pick Bypass — New Tests → <branch>` |
| To | `GUARD_NOTIFICATION_EMAIL` (comma-separated, set as secret) |
| Body | PR link, author, target branch, bypass approver, new file list, explanation text |

### 3.8 Audit Trail

Every bypass creates a permanent record directly on the PR:

1. **`contains-new-tests` label** — visible in PR list views
2. **`cherry-pick-bypass-approved` label** — records that an exception was granted
3. **Explanation comment** — authored by the approver, timestamped by GitHub
4. **Audit comment by bot** — confirms notification was sent, non-editable by the approver

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
│       ├── check_new_tests.py            # Standalone test-file detector (also used locally)
│       └── send_bypass_notification.py   # SMTP email sender (standalone callable)
└── docs/
    └── test-cherry-pick-policy.md         # End-user policy + setup guide
```

---

## 6. Configuration Reference

### GitHub Secrets (Settings → Secrets → Actions)

| Secret | Required | Example | Description |
|--------|----------|---------|-------------|
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
| `AUTH_TEAM` | `platform-owners` | Team slug for bypass authorizers |

### Branch Protection Rule

On Settings → Branches, for pattern `20????`:
- ✅ Require status checks: **`Cherry-pick policy check`**
- ✅ Do not allow bypassing the above settings

---

## 7. Security Considerations

| Risk | Mitigation |
|------|-----------|
| Unauthorized user adds bypass label | Workflow verifies label adder's org-team membership via GitHub API at runtime; fails even if label is present |
| Bypass label added before explanation | Two-step requirement: label + comment both needed; failing one fails the check |
| Duplicate email spam on re-runs | Idempotent guard: checks for `<!-- cherry-pick-bypass-notification-sent -->` marker before sending |
| `pull_request_target` privilege escalation | Workflow only reads PR metadata via API; no checkout of untrusted code |
| Token scope | Only `pull-requests: write` and `issues: write` permissions granted; no repo-write or secrets access |

---

## 8. Rollout Plan

| Phase | Action | Verification |
|-------|--------|-------------|
| **Phase 1** | Commit workflow files to `master` | Workflow appears in Actions tab; no PRs blocked yet (no branch protection rule) |
| **Phase 2** | Set GitHub Secrets with your own email as `GUARD_NOTIFICATION_EMAIL` | Open a test PR to a release branch adding a `test_*.py` file; verify block + email to yourself |
| **Phase 3** | Verify bypass flow end-to-end | Have a `platform-owners` member add bypass label + explanation; verify pass + email |
| **Phase 4** | Add branch protection rule for `20????` | Existing open cherry-pick PRs without new tests are unaffected |
| **Phase 5** | Update `GUARD_NOTIFICATION_EMAIL` to guard team DL + platform owners alias | Done |

---

## 9. Open Questions

| # | Question | Owner | Status |
|---|----------|-------|--------|
| 1 | Which GitHub team slug is the authoritative "platform owners" for sonic-mgmt? | Platform team | Open |
| 2 | Should `conftest.py` modifications (not additions) also be blocked? | Guard team | Open |
| 3 | Should `spytest/` new tests be treated differently (different ownership team)? | SpyTest owners | Open |
| 4 | Do we need a weekly digest of all bypasses, or is per-bypass email sufficient? | Guard team | Open |
| 5 | Should the policy also apply to non-release feature branches (e.g. `feature/*`)? | Platform team | Open |

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
explanation comment on the PR provides better traceability.

### C. Use a GitHub App instead of a GitHub Actions workflow
A GitHub App could react to label events in real time and have richer API access.

**Rejected:** Requires provisioning and maintaining a separate service. GitHub Actions
is already the established pattern in this repo and requires no new infrastructure.

### D. Use GitHub Environments with required reviewers
Mark the `release-branch` environment as requiring approval before deploy.

**Rejected:** Environments are designed for deployment workflows, not PR merge gates.
The label + comment pattern is more familiar to contributors already using the
`Approved for 20XXXX branch` label system.
