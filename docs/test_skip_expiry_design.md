# Design Document: Test Skip Expiry Feature

## Executive Summary

This document proposes a solution to prevent test skips from being forgotten indefinitely by introducing a category-based skip management system. Different design approaches are discussed. For some approaches skips are classified into two categories: **permanent** (indefinite skips without expiry dates) and **temporary** (time-bound skips with mandatory expiry dates). This ensures that temporary skips are revisited and either fixed or explicitly renewed, while permanent skips are properly justified. Other approaches don't rely on specifying an expiry date or classifying skips as temporary or permanent. They rely solely on GitHub issues to track skips.

---

## Table of Contents

1. [Background](#background)
2. [Problem Statement](#problem-statement)
3. [Proposed Approaches](#proposed-approaches)
   - [Approach 1: Inline Expiry Date Field](#approach-1-inline-expiry-date-field)
   - [Approach 2: Expiry Management via Separate Configuration](#approach-2-expiry-management-via-separate-configuration)
   - [Approach 3: GitHub Issue-Based Expiry Management](#approach-3-github-issue-based-expiry-management)
4. [Comparison of Approaches](#comparison-of-approaches)
5. [Selected Approach](#selected-approach)
6. [Detailed Design (Selected Approach)](#detailed-design-selected-approach)
7. [Implementation Considerations](#implementation-considerations)
8. [Migration Strategy](#migration-strategy)
9. [Testing Strategy](#testing-strategy)
10. [Future Enhancements](#future-enhancements)

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

**Goal**: Implement a category-based skip management system to ensure that skipped tests are properly classified and periodically reviewed:
1. **Permanent skips**: For fundamental limitations (e.g., ASIC not supported) without expiry dates
2. **Temporary skips**: For transient issues (e.g., bugs being fixed) with mandatory expiry dates
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

---

## Proposed Approaches

### Approach 1: Inline Category and Expiry Date Fields

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

---

### Approach 2: Expiry Management via Separate Configuration

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

---

### Approach 3: GitHub Issue-Based Expiry Management

Leverage GitHub issues as the source of truth for temporary skip expiry, with automated workflows managing issue lifecycle and expiry detection.

#### Overview

This approach separates concerns between the conditional mark YAML file and GitHub issue tracking:

1. **Permanent skips**: Continue to use category tags in the YAML file (e.g., `ASIC_NOT_SUPPORTED`, `TOPO_NOT_SUPPORTED`)
2. **Temporary skips**: Reference GitHub issues instead of hard-coded expiry dates. The issue's lifecycle (open/closed state, creation date, labels) determines skip behavior.
3. **Conditional mark plugin**: Only checks if the referenced GitHub issue is open or closed to determine skip status
4. **External automation**: A separate GitHub Actions workflow or pipeline periodically monitors issues and manages expiry

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
    description: "Skips are tracked via GitHub issues"
    requires_github_issue: true
    allowed_reasons:
      - "BUG_FIX_IN_PROGRESS"
      - "NEW_FEATURE_UNDER_DEVELOPMENT"
      - "INFRASTRUCTURE_ISSUE"

# Test skip definitions
acl/test_acl.py:
  skip:
    reason: "Skip acl for isolated-v6 topology"
    category: "TOPO_NOT_SUPPORTED"  # Permanent - no issue needed
    conditions:
      - "'isolated-v6' in topo_name"

bgp/test_bgp_session.py:
  skip:
    reason: "BGP session flap during testbed maintenance"
    category: "INFRASTRUCTURE_ISSUE"  # Temporary - requires issue
    conditions:
      - "testbed in ['testbed-01']"
      - "https://github.com/sonic-net/sonic-mgmt/issues/12345"
```

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

**1. Issue Expiry Workflow (GitHub Actions / Pipeline)**

A scheduled workflow that runs periodically (e.g., daily) to:
- Parse all conditional mark YAML files to extract referenced GitHub issues
- Query GitHub API for each issue's metadata (creation date, labels, state)
- Apply expiry logic based on chosen strategy (time-based or priority escalation)
- Take action on expired issues:
  - Close the issue (causing the skip to no longer apply)
  - Add expiry-related labels (e.g., `skip-expired`)
  - Bump priority labels if using escalation strategy
  - Optionally notify issue assignees

**2. Reporting and Dashboard Tool**

A separate tool that generates periodic reports and dashboards:
- List all active temporary skips with their associated issues
- Show issues approaching expiry (e.g., within 30/14/7 days)
- Track skip health metrics across the repository
- Provide visibility into permanent vs temporary skip distribution

**Dashboard Availability:**

The dashboard and reports can be made available through multiple channels:

1. **GitHub Project Board**: Create a GitHub Project linked to the repository that automatically tracks issues with the `test-skip` label. This provides a kanban-style view of skip status, assignees, and expiry timeline.
2. **GitHub Actions Artifact**: The daily workflow generates a report as a GitHub Actions artifact, downloadable from the workflow run page.

**3. Pre-Expiry Test Execution (Optional)**

To provide early warning, tests associated with soon-to-expire skips can be run before their expiry date:
- Run skipped tests in a non-blocking mode when expiry is approaching
- Report results to issue comments or dashboard
- Gives developers advance notice to fix issues before skips expire

**Implementation via Pipelines:**

This feature will be implemented as a scheduled Azure Pipeline that:
1. Queries for issues expiring within the next 14-30 days
2. Identifies the test cases associated with those issues from the conditional mark YAML
3. Runs those specific tests with the `--ignore-skip-for-issues` flag (bypassing the skip)
4. Collects test results and posts a summary comment on each relevant GitHub issue
5. Generates an aggregate report for review

The pipeline runs weekly (or on-demand) and operates in non-blocking mode - test failures are reported but do not block any merges or deployments.

#### Conditional Mark Plugin Behavior

The plugin's responsibility is simplified:

1. **For permanent skips**: Apply skip if category matches a permanent reason
2. **For temporary skips**: Query GitHub API to check issue state
   - If issue is **open**: Condition is evaluated to True;
   - If issue is **closed**: Condition is evaluated to False; Test skip depends on other conditions.
3. **Caching**: Cache issue state to avoid excessive API calls during test runs
4. **Fallback**: If GitHub API is unavailable, use cached state or apply skip conservatively

#### Open Issues and Considerations

**1. PR Pipeline Impact**

When the automation closes an expired issue, tests that were previously skipped will start running. This may cause PR pipelines to fail if the underlying issue is not fixed.

- **Pro**: Creates forcing function - developers must address the issue
- **Con**: May block unrelated PRs if expired skip affects shared tests
- **Mitigation**: Use a grace period with warnings before hard failure; provide clear error messages indicating which issue expired

**2. Nightly Test Management**

Not applicable to the public GitHub sonic-mgmt repository.

**3. Release Branch Management**

Different release branches may have different skip requirements for the same test.

- **Option A: Branch-Specific Issues and Conditional Mark Files**

  Each release branch maintains its own conditional mark YAML file with branch-specific GitHub issues. When a new release branch is created:
  1. Clone/copy relevant skip issues for the new branch (e.g., create `issue-202405` from `issue-main`)
  2. The conditional mark file in that branch references the cloned issues
  3. Each branch manages its skip lifecycle independently

  This approach ensures complete isolation between branches - fixing an issue on `main` does not affect the skip status on release branches.

- **Option B: Branch-Specific Labels on Shared Issues**

  Use a single issue with branch-specific labels (e.g., `branch:main`, `branch:202311`):
  - The conditional mark plugin checks if the issue has the label for the current branch
  - Expiry automation manages labels per branch independently
  - Closing an issue removes it from all branches; removing a branch label removes it from that branch only

  This approach reduces issue duplication but adds complexity in label management.

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

## Comparison of Approaches

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

### **Previous Recommendation: Approach 1 (Inline Category and Expiry Date Fields)**

**Rationale**:
1. **Principle of Locality**: Category and expiry date are most relevant in context of the skip definition
2. **Simplicity**: Minimal conceptual overhead for users
3. **Explicit**: No ambiguity about which skip entry expires when or its category
4. **Easier Implementation**: Straightforward to parse and validate categories and expiry dates
5. **Natural Extension**: Fits the existing YAML structure pattern

---

## Detailed Design (Selected Approach)

> **Note**: This section describes the detailed design for Approach 3 (GitHub Issue-Based Expiry Management), which has been selected for implementation. The original detailed design for Approach 1 is preserved below for reference.

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

### 1. YAML Structure Definition

```yaml
# Top-level category definitions
skip_categories:
  permanent:
    description: "Skips are indefinite and do not require GitHub issues"
    requires_github_issue: false
    allowed_reasons:
      - "ASIC_NOT_SUPPORTED"
      - "TOPO_NOT_SUPPORTED"
      - "FEATURE_NOT_APPLICABLE"
  temporary:
    description: "Skips require a GitHub issue for tracking and expiry"
    requires_github_issue: true
    allowed_reasons:
      - "BUG_FIX_IN_PROGRESS"
      - "NEW_FEATURE_UNDER_DEVELOPMENT"
      - "INFRASTRUCTURE_ISSUE"

# Individual test skip definitions
<test_path>:
  skip:
    reason: "<human-readable skip reason>"
    category: "<CATEGORY_NAME>"  # Must match allowed_reasons
    issue: "<GitHub issue URL>"  # Required for temporary category
    conditions: [...]
    conditions_logical_operator: "and"  # or "or"
  xfail:
    reason: "<human-readable xfail reason>"
    category: "<CATEGORY_NAME>"
    issue: "<GitHub issue URL>"  # Required for temporary category
    conditions: [...]
```

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

Highlevel structure of the workflow.

```yaml
# .github/workflows/skip-expiry-check.yml
name: Skip Expiry Check

on:
  schedule:
    - cron: '0 8 * * *'  # Daily at 8 AM UTC
  workflow_dispatch:  # Allow manual trigger

jobs:
  check-expiry:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Parse conditional mark files
        run: |
          python scripts/parse_skip_issues.py \
            --config tests/common/plugins/conditional_mark/tests_mark_conditions.yaml \
            --output issues.yaml

      - name: Check issue expiry
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          python scripts/check_issue_expiry.py \
            --issues issues.yaml \
            --expiry_config tests/common/plugins/conditional_mark/expiry_config.yaml \

      - name: Generate report
        run: |
          python scripts/generate_skip_report.py \
            --issues issues.yaml \

      - name: Post report to issue
        if: github.event_name == 'schedule'
        uses: peter-evans/create-or-update-comment@v4
        with:
          issue-number: 99999  # Tracking issue for skip reports
          body-path: report.md
```

### 3. Pre-Expiry Test Execution

To provide early warning before skips expire, implement a pre-expiry test mode:

```yaml
# .github/workflows/pre-expiry-tests.yml
name: Pre-Expiry Test Validation

on:
  schedule:
    - cron: '0 2 * * 0'  # Weekly on Sunday at 2 AM UTC

jobs:
  validate-expiring-skips:
    runs-on: ubuntu-latest
    steps:
      - name: Find expiring issues (within 30 days)
        run: |
          python scripts/find_expiring_issues.py \
            --within-days 30 \
            --output expiring_tests.txt

      - name: Run expiring tests (non-blocking)
        continue-on-error: true
        run: |
          pytest $(cat expiring_tests.txt) \
            --ignore-skip-for-issues \
            --tb=short \
            | tee test_results.txt

      - name: Report results to issues
        run: |
          python scripts/report_test_results.py \
            --results test_results.txt \
            --comment-on-issues
```

### 4. Release Branch Management

To handle skips across multiple release branches:

**Recommended Approach: Option A: Branch-Specific Issues and Conditional Mark Files**

### 5. Error Messages

#### Issue Not Found
```
ERROR: GitHub issue not found for test 'bgp/test_bgp_session.py'.
Issue URL: https://github.com/sonic-net/sonic-mgmt/issues/12345
Please verify the issue URL is correct and accessible.
```

#### Issue Closed (Test Will Run)
```
INFO: Skip no longer active for test 'bgp/test_bgp_session.py'.
GitHub issue #12345 is closed. Test will run normally.
If the underlying issue is not fixed, reopen the issue or create a new one.
```

#### Issue Expiring Soon (Warning)
```
WARNING: Skip expiring soon for test 'bgp/test_bgp_session.py'.
GitHub issue #12345 will expire in 14 days (created: 2025-08-01).
Please fix the underlying issue or document why more time is needed.
```

#### API Unavailable
```
WARNING: Cannot reach GitHub API to check issue state.
Fallback behavior: Applying skip for test 'bgp/test_bgp_session.py'.
Cached state from 2 hours ago: issue #12345 was open.
```
