# Sample Tests for Category-Based Skip Management

This directory contains sample tests and configuration to demonstrate and test the new category-based skip management feature in the conditional_mark plugin.

## Directory Contents

- **test_category_permanent.py** - Tests demonstrating permanent skip categories
- **test_category_temporary.py** - Tests demonstrating temporary skip categories with expiry dates
- **test_backward_compat.py** - Tests demonstrating backward compatibility with old format
- **test_validation_errors.py** - Tests with intentional errors for validation testing
- **sample_mark_conditions.yaml** - Complete example configuration with all features
- **README.md** - This file

## How to Run Sample Tests

### Important: Use `--rootdir` to Avoid Dependency Issues

The sample tests must be run with `--rootdir=.` to avoid loading the parent `conftest.py` which has heavy dependencies.

### Recommended: Use the Test Runner Script

The easiest way to run the sample tests:

```bash
cd tests/common/plugins/conditional_mark/sample_tests
./run_sample_tests.sh
```

### Manual Test Run (Within sample_tests directory)

**Always run from within the sample_tests/ directory:**

```bash
cd tests/common/plugins/conditional_mark/sample_tests

# Basic test - verify tests work
python -m pytest --rootdir=. test_backward_compat.py -v

# Test all sample tests
python -m pytest --rootdir=. . -v

# Test with the conditional mark plugin enabled
python -m pytest --rootdir=. . \
    --mark-conditions-files sample_mark_conditions.yaml \
    --testbed sample-testbed \
    --testbed_file sample_testbed.yaml \
    -v
```

**Key point:** Always use `--rootdir=.` when running pytest to prevent loading the parent conftest.py.

### Why the `--rootdir=.` Flag?

Without it, pytest looks for conftest files in parent directories and loads the main `tests/conftest.py`, which requires many dependencies (scapy, ansible modules, etc.) that aren't needed for these simple sample tests.

### Test Specific Scenarios

**Always run from the sample_tests/ directory with --rootdir=.**

**1. Test Permanent Skips:**
```bash
cd tests/common/plugins/conditional_mark/sample_tests
python -m pytest --rootdir=. test_category_permanent.py -v
```

**2. Test Temporary Skips:**
```bash
cd tests/common/plugins/conditional_mark/sample_tests
python -m pytest --rootdir=. test_category_temporary.py -v
```

**3. Test Backward Compatibility:**
```bash
cd tests/common/plugins/conditional_mark/sample_tests
python -m pytest --rootdir=. test_backward_compat.py -v
```

**4. Test Validation Errors:**

Uncomment the validation error examples in `sample_mark_conditions.yaml` and run:

```bash
cd tests/common/plugins/conditional_mark/sample_tests
python -m pytest --rootdir=. test_validation_errors.py \
    --mark-conditions-files sample_mark_conditions.yaml -v
```

This should fail with validation error messages.

## Expected Behavior

### Permanent Skips
- Tests with `ASIC_NOT_SUPPORTED`, `TOPO_NOT_SUPPORTED`, or `FEATURE_NOT_APPLICABLE` categories
- No expiry date required
- Skip indefinitely when conditions match

### Temporary Skips
- Tests with `BUG_FIX_IN_PROGRESS`, `NEW_FEATURE_UNDER_DEVELOPMENT`, or `INFRASTRUCTURE_ISSUE` categories
- Expiry date is mandatory (max 180 days from today)
- Skip until expiry date, then behavior depends on `expiry_action`:
  - `fail` (default): Test marked as failed with expired message
  - `warn`: Warning logged, test runs normally
  - `run`: Test runs normally without warning

### Backward Compatibility
- Tests without `category` field work as before
- No validation errors for legacy format
- Allows gradual migration to new format

### Validation Errors

The following configurations will cause validation errors:

1. **Invalid Category**: Category not in `allowed_reasons`
2. **Missing Expiry**: Temporary category without `expiry_date`
3. **Invalid Expiry**: Permanent category with `expiry_date`
4. **Expiry Too Far**: Date exceeds `max_expiry_days` (180 days)
5. **Invalid Format**: Date not in YYYY-MM-DD format

## Testing Different Platforms/Topologies

To test platform/topology-specific skips, you can simulate different environments:

```bash
# Test as if running on VS platform
# Modify the DUT facts or use actual VS testbed

# Test as if running on specific topology
# Use appropriate testbed configuration
```

## Modifying the Sample Configuration

The `sample_mark_conditions.yaml` file is heavily commented. You can:

1. **Add new categories**: Modify the `skip_categories` section
2. **Add new test skips**: Follow the examples provided
3. **Test validation**: Uncomment the validation error examples
4. **Adjust expiry dates**: Change dates to test expiry behavior

## Validation Error Testing

To see validation errors in action:

1. Open `sample_mark_conditions.yaml`
2. Scroll to the "VALIDATION ERROR EXAMPLES" section
3. Uncomment one or more examples
4. Run pytest - you should see detailed validation error messages

Example validation error output:
```
ERROR: Invalid category 'INVALID_CATEGORY_NAME' for skip mark in 'sample_tests/test_validation_errors.py::test_invalid_category'.
Allowed categories:
  Permanent: ASIC_NOT_SUPPORTED, TOPO_NOT_SUPPORTED, FEATURE_NOT_APPLICABLE
  Temporary: BUG_FIX_IN_PROGRESS, NEW_FEATURE_UNDER_DEVELOPMENT, INFRASTRUCTURE_ISSUE
```

## Key Features Demonstrated

1. **Category-based classification** - Clear separation of permanent vs temporary skips
2. **Expiry enforcement** - Mandatory expiry dates for temporary skips
3. **Validation** - Load-time validation of categories and expiry dates
4. **Backward compatibility** - Old format still works without changes
5. **Flexible expiry actions** - Control behavior when skips expire
6. **Multiple marks** - Same test can have skip and xfail with different rules

## Integration with Existing Tests

To integrate this feature with existing test suites:

1. Add `skip_categories` section to your `tests_mark_conditions.yaml`
2. Gradually add `category` and `expiry_date` fields to existing skips
3. Use permanent categories for fundamental limitations
4. Use temporary categories for bugs and ongoing work
5. Keep existing skips without categories for backward compatibility

## Troubleshooting

**Issue**: Tests not skipping as expected
- Check that conditions match your test environment
- Verify category names match exactly (case-sensitive)
- Check expiry dates haven't passed

**Issue**: Validation errors
- Ensure category is in `allowed_reasons`
- Check temporary skips have `expiry_date`
- Check permanent skips don't have `expiry_date`
- Verify date format is YYYY-MM-DD

**Issue**: Can't find basic facts for DUT
- Ensure testbed is properly configured
- Check inventory file exists
- Verify DUT is accessible via Ansible

## Next Steps

After testing with these samples:

1. Review the implementation in `__init__.py`
2. Add categories to real test skips gradually
3. Monitor expiring skips and update as needed
4. Customize categories for your needs (optional)

## Questions or Issues?

Refer to the design document: `docs/test_skip_expiry_design.md`
