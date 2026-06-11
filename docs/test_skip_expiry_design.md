# Design Document: Test Skip Expiry Feature

## Executive Summary

This document proposes a solution to address the issue of test skips being left in place indefinitely by introducing a structured skip management system. The selected direction is **Approach 3: GitHub Issue-Based Expiry Management**, which uses GitHub issue lifecycle and automation to govern temporary exceptions while keeping permanent skips explicit. Alternative approaches that were evaluated (Approach 1 and Approach 2) are retained in the appendix for historical context.

---

## Table of Contents

1. [Background](#background)
2. [Problem Statement](#problem-statement)
3. [Overview Of GitHub Issue-Based Expiry Management](#overview-of-github-issue-based-expiry-management)
   - [YAML Structure](#yaml-structure)
   - [Expiry Detection Strategies](#expiry-detection-strategies)
     - [Strategy A: Time-Based Expiry from Issue Creation](#strategy-a-time-based-expiry-from-issue-creation)
     - [Strategy B: Priority Tag Escalation](#strategy-b-priority-tag-escalation)
   - [Automation Components](#automation-components)
     - [1. PR Review Gate Workflow](#1-pr-review-gate-workflow)
     - [2. Issue Expiry Workflow](#2-issue-expiry-workflow)
     - [3. Reporting and Dashboard Tool](#3-reporting-and-dashboard-tool)
     - [4. Pre-Expiry Test Execution (Optional)](#4-pre-expiry-test-execution-optional)
4. [Detailed Design Of GitHub Issue-Based Expiry Management](#detailed-design-of-github-issue-based-expiry-management)
   - [1. Issue Expiry Workflow Details](#1-issue-expiry-workflow-details)
   - [2. Reporting and Dashboard Tool](#2-reporting-and-dashboard-tool)
5. [Issues and Considerations](#issues-and-considerations)
6. [Appendix A: Detailed Description: Priority Tag Escalation](#appendix-a-detailed-description-priority-tag-escalation)
7. [Appendix B: Archived Alternative Approaches](#appendix-b-archived-alternative-approaches)
   - [A.1 Approach 1: Inline Category and Expiry Date Fields](#a1-approach-1-inline-category-and-expiry-date-fields)
     - [Structure Example](#structure-example)
     - [Advantages](#advantages)
     - [Disadvantages](#disadvantages)
   - [A.2 Approach 2: Expiry Management via Separate Configuration](#a2-approach-2-expiry-management-via-separate-configuration)
     - [Structure Example](#structure-example-1)
     - [Advantages](#advantages-1)
     - [Disadvantages](#disadvantages-1)
   - [A.3 Comparison of Approaches](#a3-comparison-of-approaches)
   - [A.4 Previous Recommendation (Superseded)](#a4-previous-recommendation-superseded)

---

## Background

The `tests_mark_conditions.yaml` file serves as a centralized location for defining test skips and their conditions. The pytest plugin `conditional_mark` processes this file to automatically skip tests based on platform, topology, release version, and other conditions.

While this consolidation improves maintainability, tests can be skipped and forgotten, leading to:
- Tests remaining skipped long after issues are resolved
- Technical debt accumulation
- Reduced test coverage
- Loss of visibility into why tests were skipped

## Problem Statement

**Goal**: Implement a category-based exception management system to ensure skip/xfail exceptions are properly classified and periodically reviewed:

1. **Permanent skips**: For fundamental limitations (e.g., ASIC not supported) without expiry dates
2. **Temporary exceptions**: For transient issues (e.g., bugs being fixed) with mandatory expiry dates
3. Tests must be re-enabled if the underlying issue is resolved
4. Temporary skips must be updated with a new expiry date if the issue persists

**Requirements**:
- Two distinct skip categories: permanent and temporary
- Enforce expiry dates for temporary skips
- Validate category-specific allowed reasons
- Clear handling of expired skips through soft escalation, reporting, and explicit owner notification
- Timezone-aware date handling for consistency across global teams
- Minimal disruption to existing workflows
- Clear reporting of expired and miscategorized skips

**NOTE** The conditional mark files support both `skip:` and `xfail:`. Governance policy:
- `xfail:` entries with an issue are temporary exceptions and must be tracked by expiry workflow.
- `skip:` entries with an issue are also temporary exceptions and must be tracked by expiry workflow.
- `skip:` entries without an issue are permanent skips.

## Overview Of GitHub Issue-Based Expiry Management

> **NOTE** Approach 1 and Approach 2 were evaluated during design exploration and are now moved to [Appendix A](#appendix-a-archived-alternative-approaches).

This approach separates concerns between the conditional mark YAML file and GitHub issue tracking.

- **Permanent skips** are `skip:` entries without a GitHub issue.
- **Temporary exceptions** are `xfail:` or `skip:` entries with GitHub issue.

The design identifies external automation workflows and reporting tools to identify, manage and track skipped issues.

### YAML Structure

There is no structural change with this design or approach.

### Expiry Detection Strategies

This section describes two methods to classify an issue as expired.

1. Strategy A: Time-Based Expiry from Issue Creation is chosen.
2. Strategy B: Priority Tag Escalation

Chosen strategy is **Strategy A: Time-Based Expiry from Issue Creation**.

#### Strategy A: Time-Based Expiry from Issue Creation

- Calculate expiry based on issue creation date plus a configurable duration (e.g., 6 months)
- The automation workflow marks the issue as expired when the expiry threshold is reached
- On expiry, the workflow adds the configured expired label and posts an issue comment that `@` mentions designated skip maintainers for triage
- Initial expiry thresholds can be calibrated based on historical analysis of how long issues have been open

```
Issue #12345 created: 2025-08-01
Expiry policy: 6 months from creation
Expiry date: 2026-02-01
Today: 2026-02-18
Status: EXPIRED → Workflow adds expired label and comments with maintainer mentions
```

> **NOTE:** The current GitHub Actions token for this workflow has write access to `sonic-net/sonic-mgmt` only. Although conditional mark parsing can detect issue URLs from any GitHub repository, expiry tagging/commenting actions are applied only to issues in `sonic-net/sonic-mgmt`. For issues tracked in other repositories (for example `sonic-net/sonic-buildimage`), an equivalent tracking issue must exist in `sonic-net/sonic-mgmt` (and be referenced in conditional marks) for this workflow to manage expiry state.

#### Strategy B: Priority Tag Escalation

- Issues are assigned initial priority tags (e.g., P3) with associated time-to-expiry values
- As time passes, priority is automatically escalated (P3 → P2 → P1 → P0)
- Each priority level has a defined duration before escalation
- Final escalation (P0 expiry) results in soft escalation via expired labeling and maintainer notification comments

```
Priority Tag Timeline:
  P3: Initial assignment, 3 months to escalate
  P2: Elevated priority, 2 months to escalate
  P1: High priority, 1 month to escalate
  P0: Critical, 2 weeks to maintainer escalation
```

### Automation Components

##### 1. PR Review Gate Workflow

A workflow is triggered on PR events (opened, reopened, synchronize, ready_for_review) with path filter for conditional mark YAML files, for example:
- `tests/common/plugins/conditional_mark/**/*.yaml`
- `tests/common/plugins/conditional_mark/**/*.yml`

Workflow responsibilities:
- Detect if the PR changes any conditional mark YAML files.
- Auto-request review from configured leads and/or feature CODEOWNERS.
- Optionally post a sticky comment tagging leads for visibility.
- Fail fast only for policy violations (for example, missing issue on temporary exception), not for notification steps.

Implementation notes:
- Prefer event-based PR trigger over scheduled scanning of all open PRs.
- Enforce final approval through branch protection with "Require review from Code Owners".
- Keep reviewer tagging idempotent (avoid repeated review requests/comments on every sync).

> **Note:** This workflow will be implemented by modifying the existing workflow at `.github/workflows/assignReviewers.yaml` rather than creating a new workflow file.


##### 2. Issue Expiry Workflow

This workflow prevents protected GitHub issues from being closed. When an issue is closed, it scans all conditional mark files named `test_mark_conditions*.yaml` on `main` and on a configured list of release branches, extracts every GitHub issue referenced in `skip` and `xfail` conditions, and checks whether the closed issue is still present in any of those files. If it is, the workflow posts a comment explaining that the issue cannot be closed until the conditional mark entry is removed, then reopens the issue.

> **NOTE:** The current GitHub Actions token for this workflow has write access to `sonic-net/sonic-mgmt` only. Although conditional mark parsing can detect issue URLs from any GitHub repository, expiry tagging/commenting actions are applied only to issues in `sonic-net/sonic-mgmt`. For issues tracked in other repositories (for example `sonic-net/sonic-buildimage`), an equivalent tracking issue must exist in `sonic-net/sonic-mgmt` (and be referenced in conditional marks) for this workflow to manage expiry state.

> **NOTE** See "Detailed Design Of GitHub Issue-Based Expiry Management" section for more details.

##### 3. Reporting and Dashboard Tool

A separate tool that generates periodic reports and dashboards:

- List all active temporary skips with their associated issues
- Show issues approaching expiry (e.g., within 30/14/7 days) based on Priority label periods
- Track skip health metrics across the repository
- Provide visibility into permanent vs temporary skip distribution

> **NOTE** See "Detailed Design Of GitHub Issue-Based Expiry Management" section for more details.

#### 4. Pre-Expiry Test Execution (Optional)

To provide early warning, tests associated with soon-to-expire skips can be run before their expiry date:
- Run skipped tests in a non-blocking mode when expiry is approaching
- Report results to issue comments or dashboard
- Gives developers advance notice to fix issues before maintainer escalation

**Implementation via Pipelines:**

This feature will be implemented as a scheduled Azure Pipeline that:
1. Queries for issues in the conditional mark file
2. Identifies the test cases associated with those issues from the conditional mark YAML
3. Runs those specific tests with the `--ignore-skip-for-issues` flag (bypassing the skip)
4. Collects test results and posts a summary comment on each relevant GitHub issue
5. Generates an aggregate report for review

The pipeline runs weekly (or on-demand) and operates in non-blocking mode - test failures are reported but do not block any merges or deployments.

## Detailed Design Of GitHub Issue-Based Expiry Management

### 1. Issue Expiry Workflow Details

The solution is implemented as a GitHub Actions workflow that listens for issue close events on the repository. When an issue is closed, the workflow runs on the main branch and evaluates whether the issue is still referenced by any conditional mark configuration.

At a high level, the workflow performs the following steps.
* It checks out the repository and fetches a configured set of release branches that should also be examined.
* Runs a Python-based parser that scans all conditional mark files matching the pattern `test_mark_conditions*.yaml` from the main checkout and from each allowed branch.
* Aggregates all GitHub issue numbers referenced in `skip` and `xfail` condition lists and determines whether the closed issue is present in that combined set.

If the closed issue is found in any conditional mark file across the examined branches, the workflow treats the issue as protected. In that case, it posts a comment explaining that the issue cannot be closed until the corresponding conditional mark entry is removed, and then reopens the issue automatically.

The implementation is designed so that branch coverage is configurable through an allowlist of branches. This ensures that an issue cannot be closed simply because it has been removed from the main branch while it is still actively referenced in one or more maintained release branches.

The workflow operates on each issue close event independently. If multiple issues are closed around the same time, GitHub triggers separate workflow runs, and each run evaluates the specific issue that caused the event against the combined conditional mark references from all configured branches.

### 2. Reporting and Dashboard Tool

The report is generated from conditional mark YAML entries and GitHub issue metadata, and highlights three mandatory buckets:

1. **Permanently skipped entries (no associated issue)**
  - Definition: `skip:` entries that do not have any associated GitHub issue.
  - Purpose: Visibility for long-lived exclusions that require periodic product/test ownership review.

2. **Going to expire soon**
  - Definition: temporary exceptions (`xfail:` with issue and `skip:` with issue) whose computed time to expire is within `N` days.
  - `N` is driven by `warning_days` in `expiry_config.yml`.
  - Example with `warning_days: [30, 14, 7]`:
    - Include issues where `days_to_expire <= 30` (and not expired), and annotate threshold hits at 30/14/7.
  - Purpose: Early warning so owners can fix, convert, or justify before maintainer escalation is triggered.

3. **Already expired (immediate attention)**
  - Definition: temporary exceptions where issue is already crossed the configured time to expire.
  - Purpose: Escalation list for immediate triage and remediation.

Recommended output fields per row:
- Test path, mark type (`skip`/`xfail`), issue URL/ID (if any), owner/assignee, assignee status (`assigned`/`unassigned`), assignment note, current stage, `days_to_p0`, bucket, extension label, extension days, extended due date, last update timestamp.

**Dashboard Availability:**

Recommended approach is to use one dedicated GitHub Project (Projects v2) and have the daily workflow sync report rows into that project.

What must be set up before the workflow runs (one-time setup):

1. Create a dedicated GitHub Project for skip governance (for example, "Test Skip Governance").
2. Create custom fields in that project:
  - Bucket
  - DaysToExpiry
  - Owner
  - AssigneeStatus
  - AssignmentNote
  - MarkType
  - LastSeen
3. Create views in the project UI:
  - Permanently skipped (no issue)
  - Expiring soon
  - Expired
4. Add project fields for extension tracking if the project will be used as the operational dashboard:
  - ExtensionLabel
  - ExtensionDays
  - ExtendedDueDate
5. Store required credentials/secrets for workflow API access.

What the workflow does:

1. Generates normalized report JSON/CSV in the daily run.
2. Upserts one project item per tracked row (issue-linked exception or permanent-skip record).
3. Updates project custom fields on every run.
4. Publishes the same JSON/CSV as build artifact for audit/debug.
5. Includes maintainer-extension metadata in both the project sync and exported artifacts so exemption usage is visible during review.
6. Flags rows for issue-linked temporary exceptions that have no assignee, and writes that status/note to both dashboard fields and exported artifacts.

Important scope clarification:
- Project views are expected to be created manually once in GitHub UI.
- The workflow keeps items and field values up to date; it does not need to create views.

## Issues and Considerations

**1. PR Pipeline Impact**

The PR pipeline is not impacted. See "Issue Expiry Workflow" for more details.

> **NOTE** If an issue is fixed on a particular branch the entry from conditional mark can be removed and the test would be executed for that branch.

**2. Nightly Test Management**

Same as PR checker environment.

**3. Release Branch Management**

Different release branches may have different skip requirements for the same test.

- **Option A: Branch-Specific Issues and Conditional Mark Files**

  Each release branch maintains its own conditional mark YAML file with branch-specific GitHub issues. When a new release branch is created:
  1. Create new issues for the new branch based on the original issue.
  2. The conditional mark file in that branch references the cloned issues
  3. Each branch manages its skip lifecycle independently

  This approach ensures complete isolation between branches - fixing an issue on `main` does not affect the skip status on release branches.

- **Option B: Branch-Specific Labels on Shared Issues**

  Use a single issue with branch-specific labels (e.g., `branch:main`, `branch:202311`):
  - The conditional mark plugin checks if the issue has the label for the current branch
  - Expiry automation manages labels per branch independently
  - Closing an issue removes it from all branches; removing a branch label removes it from that branch only

  This approach reduces issue duplication but adds complexity in label management.

- **Option C: Conditional Mark issues can only be closed after entries are removed from all release branches**

  Use workflow to track and manage GitHub issue state and keep the issue `Open` until the issue is present in any of the conditional mark files on all the configured release branches. If the issue is closed the workflow must automatically re-open it with a comment stating the branch on which the issue is still present.

**Chosen Approach - Option C: Conditional Mark issues can only be closed after entries are removed from all release branches**

**4. Conditional Mark Hygiene**

- A periodic hygiene review is required for conditional mark files to check:
  - every temporary exception (`xfail:` with issue, `skip:` with issue) has a valid associated GitHub issue
  - every `skip:` entry without an issue is truly permanent and periodically re-validated by owners
  - if a single GitHub issue is associated with both `skip:` and `xfail:` for the same test scope, owners should evaluate whether separate issues would reduce coupled lifecycle changes
  - ownership, priority labels, and expiry metadata remain consistent with workflow reports

---

## Appendix A: Detailed Description: Priority Tag Escalation

A scheduled workflow that runs periodically (e.g., daily) to:
- Parse all conditional mark YAML files to extract referenced GitHub issues
- Query GitHub API for each issue's metadata (creation date, labels, state)
- Check assignee metadata for each tracked issue and flag issues with no assignee
- Apply Priority tag based escalation logic
- Check whether one of the configured skip maintainers has applied a maintainer-extension label in the form `skip-maintainer-extension-N`, where `N` is the number of extension days granted
- Take action on expired issues:
  - Add expiry-related labels (e.g., `sonic-wf-priority-3`, `sonic-wf-priority-2` etc.)
  - Bump priority labels if using escalation strategy
  - Add an explicit expired label when P0 duration is exceeded
  - Post or update an issue comment that `@` mentions configured skip maintainers
  - Surface active maintainer-extension labels in the generated report
  - Optionally notify issue assignees in the same comment

**Issue Comment Generation:**

The workflow generates issue comments to make escalation and expiry dates explicit:

- **When workflow adds a priority label (P3, P2, P1, P0)**: Post a comment such as `"Priority tag [skip-wf-priority-N] was added. This issue will be escalated to the next priority / expire in M days on [date]."`
- **When anyone deletes a workflow-applied priority label**: Post a comment such as `"Priority tag [skip-wf-priority-N] was deleted by @[user]. This label is workflow-managed and manual deletion does not change expiry timeline calculations."`
- **When a designated skip maintainer adds `skip-maintainer-extension-N`**: Post a comment such as `"Expiry extension granted for N days; next expiry on [date]."`
- **When a designated skip maintainer removes `skip-maintainer-extension-N`**: Post a comment such as `"Expiry extension canceled by maintainer @[maintainer] on [date]. Issue is now considered expired."`
- **Idempotency**: Comments use deterministic markers so repeated runs do not create duplicates for the same event.

**Maintainer registry**

- Maintain a dedicated registry file for governance leads, recommended as `.github/SKIP_MAINTAINERS.yml`
- The file contains the GitHub usernames that should be mentioned when a temporary skip reaches its expired state
- This keeps the escalation list explicit, reviewable, and independent of issue assignee churn
- Maintainer-extension labels are only honored when they were applied by one of the usernames listed in this file

**Maintainer extension labels**

- A designated skip maintainer may grant a grace period by adding a label in the form `skip-maintainer-extension-N`
- `N` is interpreted as calendar days of temporary extension starting from the moment that label was applied (i.e., `extension_due_date = label_applied_at + N`)
- The workflow must validate that the label was applied by a configured skip maintainer before honoring it in reporting
- A maintainer may add the label multiple times as each extension period runs out (e.g., add `skip-maintainer-extension-30`, and after 30 days add it again to grant another 30-day window)
- Because the same label name can appear multiple times in the issue timeline, the workflow must use the `labeled` event timestamp from the GitHub issue timeline API for each occurrence rather than relying solely on currently attached labels
- An extension is considered **active** only if `today < label_applied_at + N`; expired extension occurrences are disregarded
- When multiple authorized extension label occurrences are present (same or different `N`), the workflow selects the one whose computed `extension_due_date` is furthest in the future and still active; all occurrences are preserved in the report artifacts for auditability


## Appendix B: Archived Alternative Approaches

This appendix preserves earlier design explorations for historical reference. These approaches are not the selected implementation path.

### A.1 Approach 1: Inline Category and Expiry Date Fields

Add `category` and `expiry_date` fields directly within each skip/xfail definition in the YAML file, with skip categories defined at the top level.

#### Structure Example

```yaml
# Define skip categories at the top of the file
skip_categories:
  permanent:
    description: "Skips are indefinite and do not require expiry dates"
    requires_expiry_date: false
    allowed_reasons:
      - "ASIC_NOT_SUPPORTED"
      - "TOPO_NOT_SUPPORTED"
      - "FEATURE_NOT_APPLICABLE"
  temporary:
    description: "Skips must have expiry date"
    requires_expiry_date: true
    max_expiry_days: 180  # 6 months from today
    allowed_reasons:
      - "BUG_FIX_IN_PROGRESS"
      - "NEW_FEATURE_UNDER_DEVELOPMENT"
      - "INFRASTRUCTURE_ISSUE"

# Test skip definitions
acl/test_acl.py:
  skip:
    reason: "Skip acl for isolated-v6 topology"
    category: "TOPO_NOT_SUPPORTED"  # Must match allowed_reasons in permanent
    conditions:
      - "'isolated-v6' in topo_name and https://github.com/sonic-net/sonic-mgmt/issues/18077"
  xfail:
    reason: "Test case has issue on the t0-isolated-d256u256s2 topo."
    expiry: "2025-02-15"
    conditions:
      - "'t0-isolated-d256u256s2' in topo_name and platform in ['x86_64-nvidia_sn5640-r0']"

bgp/test_bgp_session.py:
  skip:
    reason: "Infrastructure issue with BGP session setup"
    category: "INFRASTRUCTURE_ISSUE"  # Must match allowed_reasons in temporary
    expiry_date: "2025-06-01"  # Required for temporary category
    conditions:
      - "'t1' in topo_name"
  xfail:
    reason: "Known issue on specific topology"
    category: "BUG_FIX_IN_PROGRESS"
    expiry_date: "2025-05-15"
    conditions:
      - "'t0-isolated' in topo_name"
```

#### Advantages
- **Simplicity**: Direct association between skip, category, and expiry
- **Readability**: Easy to understand requirements at a glance
- **Granularity**: Different categories and expiry dates for skip vs xfail on same test
- **Enforced Classification**: Category field makes skip purpose explicit
- **Type Safety**: Category validation prevents arbitrary skip reasons
- **Self-Documenting**: Skip categories defined in same file as skip definitions

#### Disadvantages
- **Verbosity**: Adds fields to every skip entry (category + expiry_date for temporary)
- **Scattered dates**: Harder to get overview of all upcoming expiries
- **Manual updates**: Each entry needs individual attention when extending

### A.2 Approach 2: Expiry Management via Separate Configuration

Maintain expiry dates in a separate section or file, referenced by test patterns.

#### Structure Example

```yaml
# In tests_mark_conditions.yaml
skip_categories:
  permanent:
    description: "Skips are indefinite and do not require expiry dates"
    requires_expiry_date: false
    allowed_reasons:
      - "ASIC_NOT_SUPPORTED"
      - "TOPO_NOT_SUPPORTED"
  temporary:
    description: "Skips must have expiry date"
    requires_expiry_date: true
    max_expiry_days: 180
    allowed_reasons:
      - "BUG_FIX_IN_PROGRESS"
      - "INFRASTRUCTURE_ISSUE"

test_expiry_config:
  default_expiry_days: 90  # Default for new temporary skips
  grace_period_days: 7     # Warning period before hard failure

  expiry_registry:
    # Pattern-based expiry management
    - pattern: "acl/test_acl.py"
      category: "ASIC_NOT_SUPPORTED"
      applies_to: ["skip"]

    - pattern: "bgp/test_bgp_*.py"
      category: "BUG_FIX_IN_PROGRESS"
      expiry_date: "2025-04-01"
      applies_to: ["skip"]

# Regular skip definitions with categories
acl/test_acl.py:
  skip:
    reason: "Skip acl for isolated-v6 topology"
    category: "ASIC_NOT_SUPPORTED"
    conditions:
      - "'isolated-v6' in topo_name"
```

#### Advantages
- **Centralized management**: Easy to see all expiries and categories in one place
- **Bulk operations**: Update multiple tests at once via patterns
- **Metadata**: Can add owner, tracking info, issue links
- **Non-intrusive**: Individual skip definitions less verbose
- **Easier refactoring**: Change category/expiry for multiple tests together

#### Disadvantages
- **Complexity**: Additional mapping layer increases cognitive load
- **Indirection**: Need to cross-reference two sections to understand skip
- **Pattern matching**: Risk of ambiguity or conflicts, hard to debug
- **Maintenance**: Two places to update, risk of inconsistency
- **Locality**: Category and expiry separated from skip reason, harder to review

### A.3 Comparison of Approaches

| Aspect | Approach 1: Inline Expiry | Approach 2: Separate Config | Approach 3: GitHub Issues |
|--------|---------------------------|-----------------------------|--------------------------|
| **Source of Truth** | YAML file | YAML file | YAML + GitHub Issues |
| **Expiry Definition** | Explicit date per skip | Pattern-based in registry | Issue lifecycle |
| **Code Review Required** | Yes (PR for changes) | Yes (PR for changes) | No (issue state changes) |
| **Notifications** | Custom tooling needed | Custom tooling needed | Built-in GitHub notifications |
| **External Dependencies** | None | None | GitHub API |
| **Forcing Function** | CI fails on expiry | CI fails on expiry | Maintainer escalation and reporting |
| **Context/History** | Git commit history | Git commit history | Issue discussion threads |
| **Complexity** | Low | Medium | High |
| **Offline Operation** | Yes | Yes | Limited (needs API cache) |
| **Multi-branch Support** | Native (file per branch) | Native (file per branch) | Requires tagging/cloning |
| **Bulk Operations** | Manual per-entry | Pattern-based | Via GitHub issue queries |
| **Escalation Support** | Manual | Manual | Automated via labels |

### A.4 Previous Recommendation (Superseded)

**Previous Recommendation**: Approach 1 (Inline Category and Expiry Date Fields)

**Rationale**:
1. **Principle of Locality**: Category and expiry date are most relevant in context of the skip definition
2. **Simplicity**: Minimal conceptual overhead for users
3. **Explicit**: No ambiguity about which skip entry expires when or its category
4. **Easier Implementation**: Straightforward to parse and validate categories and expiry dates
5. **Natural Extension**: Fits the existing YAML structure pattern
