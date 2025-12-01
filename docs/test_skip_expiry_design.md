# Design Document: Test Skip Expiry Feature

## Executive Summary

This document proposes a solution to prevent test skips from being forgotten indefinitely by introducing an expiry mechanism. After the expiry date, tests must run and cannot be skipped, ensuring that temporary skips are revisited and either fixed or explicitly renewed.

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

**Goal**: Implement an expiry mechanism to ensure that skipped tests are periodically reviewed and either:
1. Re-enabled if the underlying issue is resolved
2. Updated with a new expiry date if the issue persists
3. Documented with appropriate justification

**Requirements**:
- Expiry dates should be optional to maintain backward compatibility
- Clear handling of expired skips (force test to run or fail with explicit message)
- Timezone-aware date handling for consistency across global teams
- Minimal disruption to existing workflows
- Clear reporting of expired skips

---

## Proposed Approaches

### Approach 1: Inline Expiry Date Field

Add an `expiry_date` field directly within each skip/xfail definition in the YAML file.

#### Structure Example

```yaml
acl/test_acl.py:
  skip:
    reason: "Skip acl for isolated-v6 topology"
    expiry_date: "2025-03-01"  # ISO 8601 format: YYYY-MM-DD
    conditions:
      - "'isolated-v6' in topo_name and https://github.com/sonic-net/sonic-mgmt/issues/18077"
  xfail:
    reason: "Test case has issue on the t0-isolated-d256u256s2 topo."
    expiry_date: "2025-02-15"
    conditions:
      - "'t0-isolated-d256u256s2' in topo_name and platform in ['x86_64-nvidia_sn5640-r0']"

# Example without expiry (permanent skip)
acstests:
  skip:
    reason: "It is not tested for now"
    expiry_date: null  # or omit field entirely
    conditions:
      - "True"
```

#### Advantages
**Simplicity**: Direct association between skip and expiry
**Readability**: Easy to understand at a glance
**Granularity**: Different expiry dates for skip vs xfail on same test

#### Disadvantages
**Verbosity**: Adds line to every skip entry
**Scattered dates**: Harder to get overview of all upcoming expiries
**Manual updates**: Each entry needs individual attention

---

### Approach 2: Expiry Management via Separate Configuration

Maintain expiry dates in a separate section or file, referenced by test patterns.

#### Structure Example

```yaml
# In tests_mark_conditions.yaml
test_expiry_config:
  default_expiry_days: 90  # Default for new skips
  grace_period_days: 7     # Warning period before hard failure

  expiry_registry:
    # Pattern-based expiry management
    - pattern: "acl/test_acl.py"
      expiry_date: "2025-03-01"
      applies_to: ["skip", "xfail"]

    - pattern: "bgp/test_bgp_*.py"
      expiry_date: "2025-04-01"
      applies_to: ["skip"]

    - pattern: "dualtor/*"
      expiry_date: "2025-06-01"
      applies_to: ["skip", "xfail"]
      owner: "sonic-dualtor@microsoft.com"
      tracking_issue: "https://github.com/sonic-net/sonic-mgmt/issues/12345"

# Regular skip definitions remain unchanged
acl/test_acl.py:
  skip:
    reason: "Skip acl for isolated-v6 topology"
    conditions:
      - "'isolated-v6' in topo_name"
```

#### Advantages
**Centralized management**: Easy to see all expiries
**Bulk operations**: Update multiple tests at once via patterns
**Metadata**: Can add owner, tracking info
**Non-intrusive**: Existing skip definitions unchanged

#### Disadvantages
**Complexity**: Additional mapping layer
**Indirection**: Need to cross-reference to find expiry
**Pattern matching**: Risk of ambiguity or conflicts
**Maintenance**: Two places to update

---

### **Recommendation: Approach 1 (Inline Expiry Date Field)**

**Rationale**:
1. **Principle of Locality**: Expiry date is most relevant in context of the skip definition
2. **Simplicity**: Minimal conceptual overhead for users
3. **Explicit**: No ambiguity about which skip entry expires when
4. **Easier Implementation**: Straightforward to parse and validate
5. **Natural Extension**: Fits the existing YAML structure pattern

---

## Detailed Design (Recommended Approach)

### 1. YAML Structure Definition

```yaml
<test_path>:
  skip:
    reason: "<skip reason>"
    expiry_date: "<YYYY-MM-DD>"  # Optional, ISO 8601 date format
    expiry_action: "fail"  # or "warn" - what to do when expired
    conditions: [...]
    conditions_logical_operator: "and"  # or "or"

  xfail:
    reason: "<xfail reason>"
    expiry_date: "<YYYY-MM-DD>"
    expiry_action: "run"
    conditions: [...]
```

### 2. Expiry Date Format

- **Format**: ISO 8601 date format: `YYYY-MM-DD`
- **Examples**: `2025-03-15`, `2025-12-31`
- **Timezone**: All dates interpreted as UTC midnight (00:00:00 UTC)
- **Validation**: Date must be parsable and not in the past (at time of addition)

### 3. Expiry Actions

When a skip/xfail expiry date is reached:

| Action | Behavior | Use Case |
|--------|----------|----------|
| `fail` | Test fails with explicit error message | Default - forces attention |
| `warn` | Test runs, warning logged, but doesn't block | Soft reminder, gradual transition |
| `run` | Test runs normally without skip/xfail | Silent transition back to normal |

**Default**: `fail` (most conservative, ensures human review)

### 4. Handling Missing Expiry Dates

| Scenario | Behavior | Rationale |
|----------|----------|-----------|
| `expiry_date` omitted | Skip/xfail applies indefinitely | Backward compatible |
| `expiry_date: null` | Skip/xfail applies indefinitely | Explicit permanent skip |
| `expiry_date: ""` | Validation error at load time | Prevent accidents |
| Invalid date format | Validation error at load time | Fail fast |

### 5. Error Messages

#### Expired Skip (fail action)
```
SKIPPED [1] EXPIRED - Skip/xfail for test 'acl/test_acl.py::test_example' expired on 2025-01-15.
Original reason: Skip acl for isolated-v6 topology
Action required: Update skip with new expiry date or fix the underlying issue.
```

#### Load-Time Validation Error
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

**Requirement**: Existing YAML files without `expiry_date` must continue to work

**Implementation**:
- `expiry_date` field is optional
- Default behavior unchanged when field is omitted
- No breaking changes to existing skip definitions

### 4. Validation Strategy

**Load-Time Validation** (Strict):
- Date format must be valid ISO 8601
- Empty strings not allowed (use `null` or omit)

### 5. Multiple Mark Types

Tests can have both `skip` and `xfail` with different expiry dates:

```yaml
test_example.py::test_case:
  skip:
    reason: "Skip on platform A"
    expiry_date: "2025-03-01"
    conditions: ["platform == 'A'"]
  xfail:
    reason: "Known to fail on platform B"
    expiry_date: "2025-06-01"
    conditions: ["platform == 'B'"]
```

**Behavior**: Each mark evaluated independently with its own expiry

### 6. Expired Skip in CI/CD

**Recommendations**:
1. **Warning Period**: Add `expiry_action: warn` with 1-2 week grace period
2. **Automated Alerts**: Trigger alerts when skips are expiring soon
3. **Pull Request Checks**: Validate new skips have reasonable expiry dates
4. **Dashboard**: Track skip health across the repository

---

## Conclusion

The recommended approach (Approach 1: Inline Expiry Date Field) provides a simple, intuitive way to add expiry dates to test skips while maintaining backward compatibility. The implementation is straightforward, requires minimal changes to the existing codebase, and provides clear benefits in terms of test maintenance and coverage improvement.

The phased migration strategy ensures smooth adoption, and the suggested future enhancements provide a roadmap for continued improvement of the skip management system.
