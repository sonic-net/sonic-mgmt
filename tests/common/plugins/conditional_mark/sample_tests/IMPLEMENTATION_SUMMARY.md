# Category-Based Skip Management Implementation

## Summary

This implementation adds category-based skip management to the `conditional_mark` pytest plugin, as specified in `docs/test_skip_expiry_design.md` (Approach 1).

## What Was Implemented

### 1. Core Plugin Updates (`tests/common/plugins/conditional_mark/__init__.py`)

#### Added Imports
- `datetime`, `timedelta`, `timezone` for expiry date validation

#### New Functions

**`validate_skip_category(category, skip_categories, mark_name, test_path)`**
- Validates that a category exists in the allowed categories
- Returns validation status, category type (permanent/temporary), and error message
- Supports backward compatibility (no error if category not specified)

**`validate_expiry_date(expiry_date, category, category_type, skip_categories, mark_name, test_path)`**
- Validates expiry_date based on category requirements
- Checks if permanent categories have expiry dates (error)
- Checks if temporary categories are missing expiry dates (error)
- Validates date format (YYYY-MM-DD)
- Checks if date is already expired
- Validates max_expiry_days for temporary categories (default 180 days)
- Returns validation status, error message, and expired flag

**`check_expiry_and_format_reason(mark_details, mark_name, test_path, skip_categories)`**
- Main validation coordinator
- Checks both category and expiry date
- Handles expired skips based on `expiry_action`:
  - `fail` (default): Keep skip with expired message
  - `warn`: Log warning, don't apply mark
  - `run`: Silently don't apply mark
- Returns whether to apply mark, formatted reason, and validation errors

#### Modified Functions

**`load_conditions(session)`**
- Extracts `skip_categories` section from YAML
- Caches skip_categories in `session.config.cache`
- Continues to load test conditions as before

**`pytest_collection_modifyitems(session, config, items)`**
- Retrieves skip_categories from cache
- Calls validation before adding marks to tests
- Collects all validation errors
- Reports all validation errors at once (fails collection)
- Respects expiry_action when marks have expired

### 2. Sample Tests and Configuration

Created `tests/common/plugins/conditional_mark/sample_tests/` with:

- **test_category_permanent.py** - 5 test cases demonstrating permanent skips
- **test_category_temporary.py** - 8 test cases demonstrating temporary skips
- **test_backward_compat.py** - 5 test cases demonstrating backward compatibility
- **test_validation_errors.py** - 5 test cases for validation error scenarios
- **sample_mark_conditions.yaml** - Comprehensive example configuration
- **README.md** - Complete usage documentation
- **test_implementation.sh** - Validation script

## Key Features

### 1. Skip Categories

Two predefined categories in YAML:

```yaml
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
    max_expiry_days: 180
    allowed_reasons:
      - "BUG_FIX_IN_PROGRESS"
      - "NEW_FEATURE_UNDER_DEVELOPMENT"
      - "INFRASTRUCTURE_ISSUE"
```

### 2. Test Skip with Category

```yaml
acl/test_acl.py:
  skip:
    reason: "ASIC does not support ACL feature"
    category: "ASIC_NOT_SUPPORTED"  # Permanent - no expiry needed
    conditions:
      - "asic_type in ['vs']"

bgp/test_bgp.py:
  skip:
    reason: "Bug being fixed"
    category: "BUG_FIX_IN_PROGRESS"  # Temporary - expiry required
    expiry_date: "2026-06-15"
    expiry_action: "fail"  # fail, warn, or run
    conditions:
      - "release in ['202411']"
```

### 3. Backward Compatibility

Existing skips without `category` or `expiry_date` continue to work:

```yaml
legacy/test_old.py:
  skip:
    reason: "Old format skip"  # No category, no expiry - still works
    conditions:
      - "platform == 'old-platform'"
```

### 4. Validation

Load-time validation ensures:
- Categories are from allowed list
- Temporary skips have expiry dates
- Permanent skips don't have expiry dates
- Expiry dates are within max_expiry_days
- Date format is correct (YYYY-MM-DD)

Validation errors fail test collection with clear messages.

### 5. Expiry Handling

When a skip expires:
- **expiry_action: fail** (default) - Mark as skipped with "EXPIRED" message
- **expiry_action: warn** - Log warning, run test normally
- **expiry_action: run** - Run test silently

## Testing the Implementation

### Basic Validation
```bash
cd tests/common/plugins/conditional_mark/sample_tests
./test_implementation.sh
```

### Run Sample Tests
```bash
# From tests/ directory
pytest common/plugins/conditional_mark/sample_tests/ \
    --mark-conditions-files common/plugins/conditional_mark/sample_tests/sample_mark_conditions.yaml \
    -v
```

### Test with Actual Testbed
```bash
pytest common/plugins/conditional_mark/sample_tests/ \
    --mark-conditions-files common/plugins/conditional_mark/sample_tests/sample_mark_conditions.yaml \
    --testbed <testbed-name> \
    --testbed_file <testbed-file> \
    --inventory ../ansible/lab \
    -v
```

### Test Validation Errors

1. Open `sample_mark_conditions.yaml`
2. Uncomment validation error examples at bottom
3. Run pytest - should see validation errors

## Migration Path for Existing Tests

The implementation maintains **full backward compatibility**:

1. **Current State**: All existing skips in `tests_mark_conditions.yaml` work without changes
2. **Add Categories**: Define `skip_categories` at top of YAML (optional)
3. **Gradual Migration**: Add `category` and `expiry_date` to skips incrementally
4. **Enforcement**: Once ready, all skips can require categories

### Recommended Migration Steps

**Phase 1: Add Category Definition (Week 1)**
```yaml
# Add to top of tests_mark_conditions.yaml
skip_categories:
  permanent:
    # ... as shown above
  temporary:
    # ... as shown above
```

**Phase 2: Categorize High-Priority Tests (Weeks 2-4)**
- Start with frequently-run test suites
- Add `category` to obvious permanent skips
- Add `category` + `expiry_date` to bug-related skips

**Phase 3: Complete Migration (Week 5+)**
- All new skips must include category
- Remaining old skips updated
- Consider making categories mandatory

## Files Modified

1. **tests/common/plugins/conditional_mark/__init__.py**
   - Added datetime imports
   - Added 3 new validation functions (~150 lines)
   - Modified load_conditions() to extract skip_categories
   - Modified pytest_collection_modifyitems() to validate and handle expiry (~40 lines changed)

## Files Created

1. **tests/common/plugins/conditional_mark/sample_tests/test_category_permanent.py**
2. **tests/common/plugins/conditional_mark/sample_tests/test_category_temporary.py**
3. **tests/common/plugins/conditional_mark/sample_tests/test_backward_compat.py**
4. **tests/common/plugins/conditional_mark/sample_tests/test_validation_errors.py**
5. **tests/common/plugins/conditional_mark/sample_tests/sample_mark_conditions.yaml**
6. **tests/common/plugins/conditional_mark/sample_tests/README.md**
7. **tests/common/plugins/conditional_mark/sample_tests/test_implementation.sh**

## Next Steps

1. **Review Implementation**: Review the code changes in `__init__.py`
2. **Test with Real Testbed**: Run sample tests with actual testbed
3. **Plan Migration**: Decide on timeline for adding categories to existing skips
4. **Team Communication**: Inform test owners about new feature
5. **Update Documentation**: Update team docs with category guidelines
6. **Monitor Usage**: Track how categories are being used

## Design Document Reference

Full design specification: `docs/test_skip_expiry_design.md`

Key sections implemented:
- Section: "Approach 1: Inline Category and Expiry Date Fields" (lines 58-122)
- Section: "Detailed Design (Recommended Approach)" (lines 197-375)
- Section: "Skip Categories Overview" (lines 199-252)

## Benefits

1. **Clear Classification**: Every skip is now categorized by nature (permanent vs temporary)
2. **Enforced Discipline**: Temporary skips cannot linger indefinitely
3. **Backward Compatible**: No breaking changes to existing tests
4. **Comprehensive Validation**: Catches configuration errors at collection time
5. **Flexible Expiry**: Control what happens when skips expire
6. **Better Maintenance**: Easy to identify and track temporary skips

## Contact

For questions or issues:
- Review the design document: `docs/test_skip_expiry_design.md`
- Check sample tests: `tests/common/plugins/conditional_mark/sample_tests/`
- Run validation: `./test_implementation.sh`
