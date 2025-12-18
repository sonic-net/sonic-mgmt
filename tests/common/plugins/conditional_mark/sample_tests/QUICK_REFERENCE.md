# Quick Reference: Category-Based Skip Management

## YAML Configuration Template

```yaml
# At the top of your tests_mark_conditions.yaml
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
    max_expiry_days: 180  # 6 months
    allowed_reasons:
      - "BUG_FIX_IN_PROGRESS"
      - "NEW_FEATURE_UNDER_DEVELOPMENT"
      - "INFRASTRUCTURE_ISSUE"
```

## Skip Syntax Examples

### Permanent Skip (No Expiry)
```yaml
test_path/test_file.py::test_case:
  skip:
    reason: "VS platform doesn't support this feature"
    category: "ASIC_NOT_SUPPORTED"
    conditions:
      - "asic_type in ['vs']"
```

### Temporary Skip (With Expiry)
```yaml
test_path/test_file.py::test_case:
  skip:
    reason: "Bug #12345 being fixed"
    category: "BUG_FIX_IN_PROGRESS"
    expiry_date: "2026-06-15"  # YYYY-MM-DD
    expiry_action: "fail"  # fail, warn, or run (default: fail)
    conditions:
      - "release in ['202411']"
```

### Legacy Skip (Backward Compatible)
```yaml
test_path/test_file.py::test_case:
  skip:
    reason: "Old format still works"
    conditions:
      - "platform == 'old-platform'"
```

## Category Decision Tree

```
Is this a fundamental limitation that won't change?
│
├─ YES → Use PERMANENT category
│         - ASIC_NOT_SUPPORTED
│         - TOPO_NOT_SUPPORTED
│         - FEATURE_NOT_APPLICABLE
│         - NO expiry_date needed
│
└─ NO → Use TEMPORARY category
          - BUG_FIX_IN_PROGRESS
          - NEW_FEATURE_UNDER_DEVELOPMENT
          - INFRASTRUCTURE_ISSUE
          - MUST have expiry_date (max 180 days)
```

## Expiry Actions

| Action | Behavior | When to Use |
|--------|----------|-------------|
| `fail` | Test shows as SKIPPED with "EXPIRED" message | Default - forces review |
| `warn` | Test runs, warning logged | Grace period transition |
| `run` | Test runs silently | Automatic re-enable |

## Common Validation Errors

❌ **Invalid category**
```
Category 'MY_CATEGORY' not in allowed_reasons
```
Fix: Use exact category from allowed_reasons list

❌ **Missing expiry for temporary**
```
Category 'BUG_FIX_IN_PROGRESS' requires expiry_date
```
Fix: Add `expiry_date: "YYYY-MM-DD"`

❌ **Expiry on permanent**
```
Category 'ASIC_NOT_SUPPORTED' should not have expiry_date
```
Fix: Remove expiry_date field

❌ **Expiry too far**
```
expiry_date exceeds max_expiry_days (180)
```
Fix: Use date within 180 days from today

❌ **Invalid date format**
```
Invalid expiry_date format '12/31/2026'
```
Fix: Use ISO 8601 format: `2026-12-31`

## Testing Your Changes

```bash
# Validate syntax
pytest --co tests/ --mark-conditions-files path/to/your.yaml

# Run specific test
pytest tests/path/to/test.py -v

# See skip reasons
pytest tests/path/to/test.py -v -rs
```

## Quick Commands

```bash
# Find all expired skips
grep -A3 "expiry_date:" tests_mark_conditions.yaml | \
  grep "expiry_date:" | \
  awk '{print $2}' | \
  while read date; do
    [ "$date" "<" "$(date +%Y-%m-%d)" ] && echo "Expired: $date"
  done

# Count skips by category
grep "category:" tests_mark_conditions.yaml | \
  sort | uniq -c

# Find temporary skips expiring soon (next 30 days)
# (use Python/date tools for accurate calculation)
```

## Migration Checklist

- [ ] Add `skip_categories` section to YAML
- [ ] Review existing skips
- [ ] Categorize permanent skips (add category, no expiry)
- [ ] Categorize temporary skips (add category + expiry)
- [ ] Validate configuration: `pytest --co`
- [ ] Test with actual testbed
- [ ] Monitor expiring skips
- [ ] Update team documentation

## Example PR Description

```markdown
## Add skip category to test_xyz

- Category: BUG_FIX_IN_PROGRESS (temporary)
- Expiry: 2026-06-15 (6 months)
- Reason: Bug #12345 causing test failures
- Tracking: https://github.com/org/repo/issues/12345
- Expiry action: fail (review required when expires)

Once bug #12345 is fixed, this skip can be removed.
```

## Resources

- Design Doc: `docs/test_skip_expiry_design.md`
- Sample Tests: `tests/common/plugins/conditional_mark/sample_tests/`
- Plugin Code: `tests/common/plugins/conditional_mark/__init__.py`
- Full README: `tests/common/plugins/conditional_mark/sample_tests/README.md`
