# Design Document: Test Skip Expiry Feature

## Executive Summary

This document proposes a solution to prevent test skips from being forgotten indefinitely by introducing a category-based skip management system. Skips are classified into two categories: **permanent** (indefinite skips without expiry dates) and **temporary** (time-bound skips with mandatory expiry dates). This ensures that temporary skips are revisited and either fixed or explicitly renewed, while permanent skips are properly justified.

---

## Table of Contents

1. [Background](#background)
2. [Problem Statement](#problem-statement)
3. [Proposed Approaches](#proposed-approaches)
   - [Approach 1: Inline Expiry Date Field](#approach-1-inline-expiry-date-field)
   - [Approach 2: Expiry Management via Separate Configuration](#approach-2-expiry-management-via-separate-configuration)
4. [Comparison and Recommendation](#comparison-and-recommendation)
5. [Detailed Design (Recommended Approach)](#detailed-design-recommended-approach)
6. [Implementation Considerations](#implementation-considerations)
7. [Migration Strategy](#migration-strategy)
8. [Testing Strategy](#testing-strategy)
9. [Future Enhancements](#future-enhancements)

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

### **Recommendation: Approach 1 (Inline Category and Expiry Date Fields)**

**Rationale**:
1. **Principle of Locality**: Category and expiry date are most relevant in context of the skip definition
2. **Simplicity**: Minimal conceptual overhead for users
3. **Explicit**: No ambiguity about which skip entry expires when or its category
4. **Easier Implementation**: Straightforward to parse and validate categories and expiry dates
5. **Natural Extension**: Fits the existing YAML structure pattern

---

## Detailed Design (Recommended Approach)

### 0. Skip Categories Overview

The design introduces a two-tier category system to classify all test skips:

#### Permanent Category
- **Purpose**: For fundamental, unchangeable limitations
- **Expiry Requirement**: No expiry date needed (and not allowed)
- **Use Cases**:
  - `ASIC_NOT_SUPPORTED`: Hardware/ASIC fundamentally doesn't support the feature
  - `TOPO_NOT_SUPPORTED`: Test cannot run on certain topologies by design
  - `FEATURE_NOT_APPLICABLE`: Feature doesn't apply to certain configurations

**Example**:
```yaml
acl/test_acl.py:
  skip:
    reason: "ACL feature not available on VS platform"
    category: "ASIC_NOT_SUPPORTED"
    conditions:
      - "asic_type in ['vs']"
```

#### Temporary Category
- **Purpose**: For transient issues that should be resolved
- **Expiry Requirement**: Mandatory expiry date (max 180 days from today)
- **Use Cases**:
  - `BUG_FIX_IN_PROGRESS`: Known bug being actively fixed
  - `NEW_FEATURE_UNDER_DEVELOPMENT`: Feature in development, test temporarily disabled
  - `INFRASTRUCTURE_ISSUE`: Testbed/infrastructure problem being addressed

**Example**:
```yaml
bgp/test_bgp_session.py:
  skip:
    reason: "BGP session flap during testbed maintenance"
    category: "INFRASTRUCTURE_ISSUE"
    expiry_date: "2025-06-01"  # Must be within 180 days
    conditions:
      - "testbed in ['testbed-01']"
```

#### Category Selection Guidelines

User defined categories can be defined and added under the skip_categories section.

---

### 1. YAML Structure Definition

```yaml
# Top-level category definitions
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
    max_expiry_days: 180  # Maximum days from today
    allowed_reasons:
      - "BUG_FIX_IN_PROGRESS"
      - "NEW_FEATURE_UNDER_DEVELOPMENT"
      - "INFRASTRUCTURE_ISSUE"

# Individual test skip definitions
<test_path>:
  skip:
    reason: "<human-readable skip reason>"
    category: "<CATEGORY_NAME>"  # Must match one of the allowed_reasons
    expiry_date: "<YYYY-MM-DD>"  # Required if category is in temporary
    expiry_action: "fail"  # or "warn" - what to do when expired
    conditions: [...]
    conditions_logical_operator: "and"  # or "or"
  xfail:
    reason: "<human-readable xfail reason>"
    category: "<CATEGORY_NAME>"
    expiry_date: "<YYYY-MM-DD>"  # Required if category is in temporary
    expiry_action: "run"
    conditions: [...]
```

### 2. Category and Expiry Date Requirements

#### Skip Categories
- **permanent**: For fundamental limitations that won't change
  - `requires_expiry_date: false` - No expiry date needed or allowed
  - Allowed reasons (examples): `ASIC_NOT_SUPPORTED`, `TOPO_NOT_SUPPORTED`, `FEATURE_NOT_APPLICABLE`
- **temporary**: For transient issues that should be fixed
  - `requires_expiry_date: true` - Expiry date is mandatory
  - `max_expiry_days: 180` - Maximum 6 months from today
  - Allowed reasons (examples): `BUG_FIX_IN_PROGRESS`, `NEW_FEATURE_UNDER_DEVELOPMENT`, `INFRASTRUCTURE_ISSUE`

#### Expiry Date Format
- **Format**: ISO 8601 date format: `YYYY-MM-DD`
- **Examples**: `2025-03-15`, `2025-12-31`
- **Timezone**: All dates interpreted as UTC midnight (00:00:00 UTC)
- **Validation**:
  - Date must be parsable and not in the past (at time of addition)
  - For temporary category: Date must not exceed `max_expiry_days` (180 days) from today
  - For permanent category: Expiry date must not be specified

### 3. Expiry Actions

When a skip/xfail expiry date is reached:

| Action | Behavior | Use Case |
|--------|----------|----------|
| `fail` | Test fails with explicit error message | Default - forces attention |
| `warn` | Test runs, warning logged, but doesn't block | Soft reminder, gradual transition |
| `run` | Test runs normally without skip/xfail | Silent transition back to normal |

**Default**: `fail` (most conservative, ensures human review)

### 4. Category and Expiry Date Validation

| Scenario | Behavior | Rationale |
|----------|----------|-----------|----------|
| Permanent category with `expiry_date` | Validation error at load time | Permanent skips should not have expiry |
| Permanent category without `expiry_date` | Skip/xfail applies indefinitely | Expected for permanent category |
| Temporary category without `expiry_date` | Validation error at load time | Temporary skips must have expiry |
| Temporary category with `expiry_date` > 180 days | Validation error at load time | Enforce max_expiry_days limit |
| Category not in allowed_reasons | Validation error at load time | Category must be valid |
| `expiry_date: ""` | Validation error at load time | Prevent accidents |
| Invalid date format | Validation error at load time | Fail fast |
| Missing `category` field | Validation error at load time | Category is mandatory |

### 5. Error Messages

#### Expired Skip (fail action)
```
SKIPPED [1] EXPIRED - Skip/xfail for test 'bgp/test_bgp_session.py::test_example' expired on 2025-01-15.
Original reason: Infrastructure issue with BGP session setup
Category: INFRASTRUCTURE_ISSUE (temporary)
Action required: Update skip with new expiry date or fix the underlying issue.
```

#### Load-Time Validation Errors

**Invalid Category**
```
ERROR: Invalid category 'INVALID_REASON' for test 'acl/test_acl.py'.
Allowed categories:
  Permanent: ASIC_NOT_SUPPORTED, TOPO_NOT_SUPPORTED, FEATURE_NOT_APPLICABLE
  Temporary: BUG_FIX_IN_PROGRESS, NEW_FEATURE_UNDER_DEVELOPMENT, INFRASTRUCTURE_ISSUE
```

**Missing Expiry Date for Temporary Category**
```
ERROR: Missing expiry_date for test 'bgp/test_bgp.py'.
Category 'BUG_FIX_IN_PROGRESS' is temporary and requires an expiry_date.
```

**Expiry Date on Permanent Category**
```
ERROR: Invalid expiry_date for test 'acl/test_acl.py'.
Category 'ASIC_NOT_SUPPORTED' is permanent and should not have an expiry_date.
```

**Expiry Date Exceeds Maximum**
```
ERROR: expiry_date '2025-12-31' exceeds max_expiry_days (180) for test 'bgp/test_bgp.py'.
Category 'INFRASTRUCTURE_ISSUE' requires expiry within 180 days from today (2025-06-01).
```

**Invalid Date Format**
```
ERROR: Invalid expiry_date format '2025-13-45' for test 'bgp/test_bgp.py'.
Expected ISO 8601 format: YYYY-MM-DD
```

---

## Implementation Considerations

### 1. Timezone Handling

All expiry dates are interpreted as UTC midnight (00:00:00 UTC)

### 2. Date Comparison Logic

Test expires ON the expiry date (not day after).  Example - If `expiry_date: "2025-01-15"`, test expires at the start of Jan 15, 2025 UTC

### 3. Backward Compatibility

**Requirement**: Phased migration to avoid breaking existing workflows

**Implementation Strategy**:

#### Phase 1 (Migration Period - Warnings Only)
- `category` field is optional, warnings logged if missing
- `expiry_date` field is optional
- Existing skip definitions continue to work unchanged
- New skips encouraged (but not required) to use categories

#### Phase 2 (Enforcement)
- `category` field becomes mandatory (validation error if missing)
- Category-specific rules enforced:
  - Permanent categories: `expiry_date` not allowed
  - Temporary categories: `expiry_date` required
- All existing skips must be updated with valid categories

**Migration Grace Period**: 4-6 weeks recommended

### 4. Validation Strategy

**Load-Time Validation** (Strict):
- `category` field is mandatory for all skip/xfail entries
- Category must match one of the `allowed_reasons` in either permanent or temporary
- Permanent category must NOT have `expiry_date`
- Temporary category MUST have `expiry_date`
- Date format must be valid ISO 8601
- Expiry date must not exceed `max_expiry_days` (180 days) for temporary category
- Empty strings not allowed for dates
- Date must not be in the past

### 5. Multiple Mark Types

Tests can have both `skip` and `xfail` with different categories and expiry dates:

```yaml
test_example.py::test_case:
  skip:
    reason: "Skip on VS platform due to ASIC limitations"
    category: "ASIC_NOT_SUPPORTED"
    conditions: ["asic_type == 'vs'"]
  xfail:
    reason: "Known to fail on platform B, fix in progress"
    category: "BUG_FIX_IN_PROGRESS"
    expiry_date: "2025-06-01"
    conditions: ["platform == 'B'"]
```

**Behavior**: Each mark evaluated independently with its own category and expiry rules

### 6. Expired Skip in CI/CD

**Recommendations**:
1. **Warning Period**: Add `expiry_action: warn` with 1-2 week grace period
2. **Automated Alerts**: Trigger alerts when skips are expiring soon
3. **Pull Request Checks**:
   - Validate category is from allowed list
   - Validate temporary skips have expiry dates
   - Validate permanent skips do not have expiry dates
   - Validate expiry dates don't exceed max_expiry_days
   - Validate expiry dates are not in the past
4. **Dashboard**:
   - Track skip health across the repository
   - Show distribution of permanent vs temporary skips
   - Highlight skips expiring soon

---

## Conclusion

The recommended approach introduces a category-based skip management system with two distinct categories:

1. **Permanent Skips**: For fundamental limitations (ASIC/topology not supported) that don't require expiry dates
2. **Temporary Skips**: For transient issues (bugs, infrastructure) with mandatory expiry dates (max 180 days)

The inline category and expiry date fields (Approach 1) keep related information together, making it intuitive to understand skip requirements at a glance. The phased migration strategy ensures smooth adoption without disrupting existing workflows, and the comprehensive validation ensures skip hygiene from day one.
