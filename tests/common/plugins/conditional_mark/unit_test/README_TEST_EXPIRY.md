# Unit Tests for Category-Based Skip Management

## Quick Start

Run all tests:
```bash
./run_tests.sh
```

## Test Files

1. **unittest_category_expiry.py** (20 tests)
   - Programmatic tests for validation functions
   - Tests individual functions directly

2. **unittest_yaml_skip_categories.py** (18 tests)
   - YAML-based tests
   - Tests by loading configuration from YAML file
   - **Developers can edit `tests_skip_categories.yaml` to test different scenarios**

3. **tests_skip_categories.yaml**
   - Configuration file with skip_categories definition
   - Test cases demonstrating various scenarios
   - **Edit this file to quickly test new configurations**

## Skip Categories Overview

There are two types of skip categories:

### Permanent Categories
- Used for skips that won't be fixed (e.g., platform limitations)
- **Does not require** an `expiry_date`
- Examples: `ASIC_NOT_SUPPORTED`, `FEATURE_NOT_APPLICABLE`

### Temporary Categories
- Used for skips that should be fixed eventually (e.g., bugs, flaky tests)
- **Requires** an `expiry_date` (format: YYYY-MM-DD)
- Maximum expiry duration: 180 days
- Examples: `BUG_FIX_IN_PROGRESS`, `KNOWN_FLAKY_TEST`

## Expiry Actions

When a skip with an `expiry_date` has passed, you can control what happens using `expiry_action`:

### `expiry_action: "fail"` (default)
- **Fails the entire test run** when expiry date has passed
- Forces someone to address the expired skip
- Use this when you want strict accountability
- Example:
```yaml
test_case.py::test_function:
  skip:
    category: "BUG_FIX_IN_PROGRESS"
    expiry_date: "2026-03-01"
    expiry_action: "fail"  # Will fail test run after March 1, 2026
    reason: "Bug #123 being fixed"
```

### `expiry_action: "warn"`
- **Removes the skip** and runs the test
- Logs a warning message about the expired skip
- Use this when you want visibility but not enforcement
- Example:
```yaml
test_case.py::test_function:
  skip:
    category: "KNOWN_FLAKY_TEST"
    expiry_date: "2026-03-01"
    expiry_action: "warn"  # Will run test with warning after March 1, 2026
    reason: "Flaky due to timing issue"
```

### `expiry_action: "run"`
- **Removes the skip** and runs the test silently
- No warnings or errors
- Use this when you want automatic cleanup
- Example:
```yaml
test_case.py::test_function:
  skip:
    category: "BUG_FIX_IN_PROGRESS"
    expiry_date: "2026-03-01"
    expiry_action: "run"  # Will run test silently after March 1, 2026
    reason: "Waiting for feature release"
```

## How to Test Your Own Configurations

### 1. Add a New Permanent Category

Edit `tests_skip_categories.yaml`:

```yaml
skip_categories:
  permanent:
    allowed_reasons:
      - "ASIC_NOT_SUPPORTED"
      - "YOUR_NEW_CATEGORY"  # Add here
```

Add a test case:

```yaml
test_your_new.py::test_case:
  skip:
    reason: "Testing my new category"
    category: "YOUR_NEW_CATEGORY"
    conditions:
      - "True"
```

Run tests:
```bash
./run_tests.sh
```

### 2. Change Maximum Expiry Days

Edit `tests_skip_categories.yaml`:

```yaml
skip_categories:
  temporary:
    max_expiry_days: 90  # Change from 180 to 90
```

Tests will automatically validate against the new limit.

### 3. Test Expired Skips

Test expired skip with different actions:

```yaml
# Expired with fail action - will cause test run to fail
test_expired_fail.py::test_case:
  skip:
    category: "BUG_FIX_IN_PROGRESS"
    expiry_date: "2024-01-01"  # Past date
    expiry_action: "fail"  # Default behavior
    reason: "This will fail the test run"
    conditions:
      - "True"

# Expired with warn action - will run test with warning
test_expired_warn.py::test_case:
  skip:
    category: "BUG_FIX_IN_PROGRESS"
    expiry_date: "2024-01-01"  # Past date
    expiry_action: "warn"
    reason: "This will run with a warning"
    conditions:
      - "True"

# Expired with run action - will run test silently
test_expired_run.py::test_case:
  skip:
    category: "BUG_FIX_IN_PROGRESS"
    expiry_date: "2024-01-01"  # Past date
    expiry_action: "run"
    reason: "This will run silently"
    conditions:
      - "True"
```

Run tests to verify behavior matches expected expiry actions.

### 4. Test Invalid Configurations

Add test cases that should fail validation:

```yaml
# Permanent with expiry (invalid)
test_bad_permanent.py::test_case:
  skip:
    category: "ASIC_NOT_SUPPORTED"
    expiry_date: "2026-06-15"  # Should fail
    reason: "Permanent shouldn't have expiry"

# Temporary without expiry (invalid)
test_bad_temporary.py::test_case:
  skip:
    category: "BUG_FIX_IN_PROGRESS"
    # Missing expiry_date - should fail
    reason: "Temporary needs expiry"
```

## Test Coverage

### Programmatic Tests (unittest_category_expiry.py)
- Category validation (valid/invalid categories)
- Expiry date validation (format, past/future, max duration)
- Error reporting
- Backward compatibility

### YAML-Based Tests (unittest_yaml_skip_categories.py)
- Load skip_categories from YAML
- Valid permanent skips
- Valid temporary skips with expiry
- Expired skip handling
- Invalid configurations (permanent with expiry, temporary without expiry)
- Invalid categories
- Invalid date formats
- Boundary testing (180 days max)
- Backward compatibility (no category)
