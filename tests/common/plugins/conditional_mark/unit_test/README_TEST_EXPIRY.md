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

Add a test case with past date:

```yaml
test_expired_check.py::test_case:
  skip:
    category: "BUG_FIX_IN_PROGRESS"
    expiry_date: "2024-01-01"  # Past date
    reason: "This should not be applied"
```

Run tests to verify expired skip is not applied.

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
