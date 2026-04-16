# Design Document: Test Skip Expiry Feature

## Executive Summary

This document proposes a solution to address the issue of test skips being left in place indefinitely by introducing a structured skip management system. The selected direction is **Approach 3: GitHub Issue-Based Expiry Management**, which uses GitHub issue lifecycle and automation to govern temporary exceptions while keeping permanent skips explicit. Alternative approaches that were evaluated (Approach 1 and Approach 2) are retained in the appendix for historical context.

---

## Table of Contents

1. [Background](#background)
2. [Problem Statement](#problem-statement)
3. [Proposed Approaches](#proposed-approaches)
   - [Approach 3: GitHub Issue-Based Expiry Management](#approach-3-github-issue-based-expiry-management)
4. [Selected Approach](#selected-approach)
5. [Detailed Design (Selected Approach)](#detailed-design-selected-approach)
6. [Appendix A: Archived Alternative Approaches](#appendix-a-archived-alternative-approaches)

---

## Background

The `tests_mark_conditions.yaml` file serves as a centralized location for defining test skips and their conditions. The pytest plugin `conditional_mark` processes this file to automatically skip tests based on platform, topology, release version, and other conditions.

While this consolidation improves maintainability, tests can be skipped and forgotten, leading to:
- Tests remaining skipped long after issues are resolved
- Technical debt accumulation
- Reduced test coverage
- Loss of visibility into why tests were skipped

---

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
- Clear handling of expired skips (force test to run or fail with explicit message)
- Timezone-aware date handling for consistency across global teams
- Minimal disruption to existing workflows
- Clear reporting of expired and miscategorized skips

**NOTE** The conditional mark files support both `skip:` and `xfail:`. For governance and migration:
- `xfail:` entries with an issue are considered temporary exceptions and must be tracked by expiry workflow.
- `skip:` entries with an issue are treated as temporary exceptions during cleanup/migration.
- Target steady state is: permanent `skip:` entries have no issue, temporary exceptions are represented as `xfail:` entries with issue.

---

## Proposed Approaches

Approach 1 and Approach 2 were evaluated during design exploration and are now moved to [Appendix A](#appendix-a-archived-alternative-approaches) to keep the main design narrative focused on the selected implementation path.

### Approach 3: GitHub Issue-Based Expiry Management

Leverage GitHub issues as the source of truth for temporary skip expiry, with automated workflows managing issue lifecycle and expiry detection.

#### Overview

This approach separates concerns between the conditional mark YAML file and GitHub issue tracking:

1. **Permanent skips**: `skip:` entries without a GitHub issue.
2. **Temporary exceptions**: `xfail:` entries with GitHub issue, plus legacy `skip:` entries with GitHub issue during migration.
3. **Conditional mark plugin**: Checks referenced GitHub issue state to determine effective behavior.
4. **External automation**: Event-based PR gate workflow enforces review policy; scheduled workflow monitors issues and manages expiry.

#### YAML Structure

There is no structural change with this design or approach.

#### Expiry Detection Strategies

The following strategies are proposed for determining when a GitHub issue (and its associated skip) has expired:

**Strategy A: Time-Based Expiry from Issue Creation**

- Calculate expiry based on issue creation date plus a configurable duration (e.g., 6 months)
- The automation workflow closes the issue when the expiry threshold is reached
- When the conditional mark plugin sees a closed issue, it evaluates that condition to False. The final skip behavior is determined by other conditions specified for the test and `conditions_logical_operator`.
- Initial expiry thresholds can be calibrated based on historical analysis of how long issues have been open

```
Issue #12345 created: 2025-08-01
Expiry policy: 6 months from creation
Expiry date: 2026-02-01
Today: 2026-02-18
Status: EXPIRED → Issue automatically closed by workflow
```

**Strategy B: Priority Tag Escalation**

- Issues are assigned initial priority tags (e.g., P3) with associated time-to-expiry values
- As time passes, priority is automatically escalated (P3 → P2 → P1 → P0)
- Each priority level has a defined duration before escalation
- Final escalation (P0 expiry) results in issue closure

```
Priority Tag Timeline:
  P3: Initial assignment, 3 months to escalate
  P2: Elevated priority, 2 months to escalate
  P1: High priority, 1 month to escalate
  P0: Critical, 2 weeks to closure
```

#### Chosen Expiry Strategy

**Strategy B: Priority Tag Escalation**

#### Automation Components

**0. PR Review Gate Workflow (Event-Based)**

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

**1. Issue Expiry Workflow (GitHub Actions / Pipeline)**

A scheduled workflow that runs periodically (e.g., daily) to:
- Parse all conditional mark YAML files to extract referenced GitHub issues
- Query GitHub API for each issue's metadata (creation date, labels, state)
- Apply Priority tag based escalation logic
- Take action on expired issues:
  - Close the issue (causing the skip to no longer apply)
  - Add expiry-related labels (e.g., `sonic-wf-priority-3`, `sonic-wf-priority-2` etc.)
  - Bump priority labels if using escalation strategy
  - Optionally notify issue assignees

**2. Reporting and Dashboard Tool**

A separate tool that generates periodic reports and dashboards:
- List all active temporary skips with their associated issues
- Show issues approaching expiry (e.g., within 30/14/7 days) based on Priority label periods
- Track skip health metrics across the repository
- Provide visibility into permanent vs temporary skip distribution

#### Report Buckets and Warning-Day Semantics

The report is generated from conditional mark YAML entries and GitHub issue metadata, and highlights three mandatory buckets:

1. **Permanently skipped entries (no associated issue)**
  - Definition: `skip:` entries that do not have any associated GitHub issue.
  - Purpose: Visibility for long-lived exclusions that require periodic product/test ownership review.

2. **Going to expire soon (reach P0 in next N days)**
  - Definition: temporary exceptions (`xfail:` with issue, plus legacy `skip:` with issue during migration) whose computed time-to-P0 is within `N` days.
  - `N` is driven by `warning_days` in `expiry_config.yml`.
  - Example with `warning_days: [30, 14, 7]`:
    - Include issues where `days_to_p0 <= 30` (and not expired), and annotate threshold hits at 30/14/7.
  - Purpose: Early warning so owners can fix, convert, or justify before auto-close/failure impact.

3. **Already expired (immediate attention)**
  - Definition: temporary exceptions where P0 threshold is already crossed (for example, `days_to_p0 < 0`), including issues auto-closed by workflow or still open but overdue by policy.
  - Purpose: Escalation list for immediate triage and remediation.

Computation notes:
- Priority stage durations are read from `expiry_config.yml` (`pN_label_expiry_days`).
- Current stage timestamp source is issue timeline label events (workflow-applied priority labels).
- `days_to_p0` is derived from current stage start + remaining configured durations to P0.
- Buckets must be mutually exclusive in output (`expired` first, then `expiring soon`, then `permanent skip`).

Recommended output fields per row:
- Test path, mark type (`skip`/`xfail`), issue URL/ID (if any), owner/assignee, current stage, `days_to_p0`, bucket, last update timestamp.

**Dashboard Availability:**

Recommended approach is to use one dedicated GitHub Project (Projects v2) and have the daily workflow sync report rows into that project.

What must be set up before the workflow runs (one-time setup):

1. Create a dedicated GitHub Project for skip governance (for example, "Test Skip Governance").
2. Create custom fields in that project:
  - Bucket
  - DaysToP0
  - Owner
  - MarkType
  - LastSeen
3. Create views in the project UI:
  - Permanently skipped (no issue)
  - Expiring soon
  - Expired
4. Store required credentials/secrets for workflow API access.

What the workflow does:

1. Generates normalized report JSON/CSV in the daily run.
2. Upserts one project item per tracked row (issue-linked exception or permanent-skip record).
3. Updates project custom fields on every run.
4. Publishes the same JSON/CSV as build artifact for audit/debug.

Important scope clarification:
- Project views are expected to be created manually once in GitHub UI.
- The workflow keeps items and field values up to date; it does not need to create views.

**3. Pre-Expiry Test Execution (Optional)**

To provide early warning, tests associated with soon-to-expire skips can be run before their expiry date:
- Run skipped tests in a non-blocking mode when expiry is approaching
- Report results to issue comments or dashboard
- Gives developers advance notice to fix issues before skips expire

**Implementation via Pipelines:**

This feature will be implemented as a scheduled Azure Pipeline that:
1. Queries for issues in the conditional mark file
2. Identifies the test cases associated with those issues from the conditional mark YAML
3. Runs those specific tests with the `--ignore-skip-for-issues` flag (bypassing the skip)
4. Collects test results and posts a summary comment on each relevant GitHub issue
5. Generates an aggregate report for review

The pipeline runs weekly (or on-demand) and operates in non-blocking mode - test failures are reported but do not block any merges or deployments.

#### Conditional Mark Plugin Behavior

The plugin's responsibility is simplified:

1. **For permanent skips**: `skip:` entries without an associated issue are applied as in current implementation.
2. **For temporary exceptions** (`xfail:` with issue, and legacy `skip:` with issue during migration): plugin behavior remains unchanged and checks issue state.
  - If issue is **open**: Exception condition is evaluated as configured.
  - If issue is **closed**: Exception condition is evaluated to False.
3. **Caching**: Cache issue state to avoid excessive API calls during test runs (already available in current implementation of the conditional mark plugin)
4. **Fallback**: If GitHub API is unavailable, use cached state or apply skip conservatively

#### Open Issues and Considerations

**1. PR Pipeline Impact**

When the automation closes an expired issue, tests that were previously skipped will start running. This may cause PR pipelines to fail if the underlying issue is not fixed.

- **Pro**: Creates forcing function - developers must address the issue
- **Con**: May block unrelated PRs if expired skip affects shared tests
- **Mitigation**: Use a grace period with warnings before hard failure; provide clear error messages indicating which issue expired

**2. Nightly Test Management**

Not applicable. This applies to public GitHub sonic-mgmt repository issues only.

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

**Chosen Approach** - Option A - where new issues are created for each release branch and tracked separately. Automation will be required to initially create new issues for all branches.

#### Advantages

- GitHub issues provide discussion threads, linked PRs, commit references, and full history
- GitHub's notification system alerts assignees and watchers
- Issues appear in project boards, dashboards, and search results
- Expiry logic is centralized in automation
- Priority-based escalation provides graduated urgency
- Natural fit with existing GitHub-based development workflow
- Issue history captures all state changes and discussions
- Can adjust expiry policies without modifying YAML files

#### Disadvantages

- Skip definitions in YAML, skip reasons/status in GitHub - two places to check
- Requires building and maintaining the expiry workflow
- Easy to reopen a closed issue without actually fixing the problem
- Closing/reopening issues doesn't require PR approval
- Managing issues across multiple branches adds overhead

> **Note**: The existing conditional mark plugin already includes efficient GitHub issue querying with caching, so API rate limits, latency, and external dependency concerns have been addressed in the current implementation.

---

## Selected Approach

**Decision: Approach 3 (GitHub Issue-Based Expiry Management) has been selected.**

This decision was made after team discussions weighing the trade-offs between simplicity and integration with existing development workflows.

### Rationale for Selection

1. **Alignment with existing workflows**: The team already uses GitHub issues to track bugs and feature work. Linking skips to issues creates a natural connection between test status and development progress.
2. **Rich context and discussion**: GitHub issues provide a centralized place for discussing why a test is skipped, tracking progress toward a fix, and linking related PRs and commits.
3. **Built-in notification system**: GitHub's notifications, assignees, and watchers provide visibility without building custom alerting infrastructure.
4. **Dynamic expiry management**: Expiry policies can be adjusted centrally in the automation workflow without modifying individual YAML entries.
5. **Priority escalation**: The ability to automatically escalate issue priority provides graduated urgency and gives developers multiple opportunities to address issues before expiry.

### Trade-offs Accepted

- **External API dependency**: The team accepts the dependency on GitHub API availability, with caching as mitigation
- **Increased complexity**: The automation workflow and caching layer add implementation complexity
- **No code review for state changes**: Issue state changes don't require PR approval, relying instead on team discipline and visibility
- **Split context**: Information is distributed between YAML files and GitHub issues

### Implementation Approach

- **Expiry Strategy**: Strategy A (time-based expiry from issue creation) will be used initially, with a 6-month default expiry period
- **Initial calibration**: Historical analysis of existing issues will inform the initial expiry threshold
- **Soft rollout**: Use "soft expiry" mode initially (warnings only) before enabling hard failure
- **Controlled impact**: Automation will report status without automatically closing issues during the transition period

---

## Detailed Design (Selected Approach)

> **Note**: This section describes the detailed design for Approach 3 (GitHub Issue-Based Expiry Management), which has been selected for implementation. Archived alternatives are captured in Appendix A.

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Test Execution                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────┐    ┌──────────────────┐    ┌─────────────────────┐   │
│  │ tests_mark_     │───▶│ Conditional Mark │───▶│ GitHub Issue Cache  │   │
│  │ conditions.yaml │    │ Plugin           │    │                     │   │
│  └─────────────────┘    └──────────────────┘    └──────────┬──────────┘   │
│                                                             │              │
│                                                             ▼              │
│                                                  ┌─────────────────────┐   │
│                                                  │ GitHub API          │   │
│                                                  │ (Issue State Query) │   │
│                                                  └─────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                           Automation Pipeline                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────┐    ┌──────────────────┐    ┌─────────────────────┐   │
│  │ Scheduled       │───▶│ Issue Expiry     │───▶│ GitHub API          │   │
│  │ Workflow (Daily)│    │ Checker          │    │ (Issue Management)  │   │
│  └─────────────────┘    └──────────────────┘    └──────────┬──────────┘   │
│                                                             │              │
│                                                             ▼              │
│                                                  ┌─────────────────────┐   │
│                                                  │ Actions:            │   │
│                                                  │ - Close issue       │   │
│                                                  │ - Update labels     │   │
│                                                  │ - Notify assignees  │   │
│                                                  └─────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                           Reporting & Dashboard                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────┐    ┌──────────────────┐    ┌─────────────────────┐   │
│  │ Report          │───▶│ Dashboard        │───▶│ Metrics:            │   │
│  │ Generator       │    │ (Web UI)         │    │ - Expiring soon     │   │
│  └─────────────────┘    └──────────────────┘    │ - By category       │   │
│                                                  │ - By assignee       │   │
│                                                  └─────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

**NOTE** There are no changes to the conditional mark plugin with this approach.

### 1. YAML Structure Definition

There are no structural changes to the conditional mark YAML file.

**Best-practice guideline**:
- Temporary exceptions should be represented as `xfail:` entries and must include an associated GitHub issue.
- `skip:` entries should be reserved for permanent exclusions and should not carry an issue in steady state.
- Legacy `skip:` entries that include issues are migration artifacts and should be converted/cleaned up toward the target policy.

### 2. Issue Expiry Workflow

Expiry configuration governs the behavior of the workflow tools must be maintained in a separate configuration.

```yaml
# expiry_config.yml
expiry_config:
  p3_label_expiry_days: 90
  p2_label_expiry_days: 60
  p1_label_expiry_days: 30
  p0_label_expiry_days: 15
  warning_days: [30, 14, 7]  # Days before expiry to send warnings
```

The tags used by the workflow -

- Priority tags follow the pattern based on expiry configuration entries. Pattern `skip-wf-priority-<N>`. Where `<N>` indicates the priority number from the expiry configuration file.
- Auto closed issues would be labelled with `skip-wf-auto-close-<timestamp>`. The `<timestamp>` would follow `ddmmyyyyhhmm` value. If an issue is re-opened manually the subsequent run would close the issue with an updated auto-close tag.

**NOTE-1** If an issue is fixed, the corresponding test entry/entries must be removed from the conditional mark files.

**NOTE-2** An un-reviewed issue marked with P0 tag and then closed by the workflow will be skipped as usual. There is no enforcement that or check required for a user to re-open the issue and allow PR checkers to skip the test again. To handle this scenario the reporting tool would always keep the test and related issue in the report until it has been addressed or fixed.

### 3. Release Branch Management

To handle skips across multiple release branches:

**Recommended Approach: Option A: Branch-Specific Issues and Conditional Mark Files**

#### 4. Implementation Behavior

- Final auto-close action adds a timestamped label before closing: `skip-wf-auto-close-<ddmmyyyyhhmm>`.
- If the same issue is auto-closed again later (for example after manual reopen), a new timestamped auto-close label is added again, so each auto-close event is recorded distinctly.
- Priority levels are derived dynamically from `expiry_config.yml` keys matching `pN_label_expiry_days`; fixed ladders are not assumed.
- Warning comments and final close comments are idempotent through deterministic hidden markers, so repeated daily runs do not spam duplicate comments for the same threshold/stage.
- Stage source of truth is issue timeline `labeled` events for workflow priority labels (label history), not current issue label presence.
- Scan/classification includes both `xfail:` with issue and legacy `skip:` with issue during migration.
- Long-term policy target: only permanent `skip:` entries remain without issue; temporary exceptions are tracked through `xfail:` entries with issue.

#### 5. Conditional Mark Cleanup

- A round of cleanup is required for conditional mark files to check
  - if all temporary issues have a GitHub issue associated with them
  - if tests that don't have an issue associated with `skip:` are indeed permanent
  - convert/track legacy `skip:` entries that have issues as temporary migration items
  - if a GitHub issue is associated with both `skip:` and `xfail:` for a test, split into separate issues to avoid coupled lifecycle changes
  - target end state: `skip:` with no issue = permanent; `xfail:` with issue = temporary

---

## Appendix A: Archived Alternative Approaches

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
| **Forcing Function** | CI fails on expiry | CI fails on expiry | Issue closure stops skip |
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
