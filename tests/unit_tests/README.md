# Unit Tests

This directory contains unit tests for SONiC test infrastructure and fixtures. These tests are isolated from the full test environment and validate fixture behavior, helper functions, and infrastructure components independently.

## Directory Structure

```
unit_tests/
├── README.md                          # This file
├── unit_test_conftest.py             # Tests for conftest.py fixtures
└── ... (other unit test files)
```

## Running Unit Tests

### Run All Unit Tests
```bash
cd tests
python3 -m pytest --noconftest unit_tests/ -v
```

### Run Specific Test File
```bash
cd tests
python3 -m pytest --noconftest unit_tests/unit_test_conftest.py -v
```

### Run Specific Test Function
```bash
cd tests
python3 -m pytest --noconftest unit_tests/unit_test_conftest.py::test_generate_skeleton_port_info_returns_override_data -v
```

## Test Files

### unit_test_conftest.py

Tests for the `generate_skeleton_port_info` fixture in `tests/conftest.py`.

**Coverage:**
- `test_generate_skeleton_port_info_returns_override_data` - Validates override path behavior
- `test_generate_skeleton_port_info_builds_all_categories` - Validates port category matrix building (single/multiple ASIC, single/multiple linecard combinations)
- `test_generate_skeleton_port_info_handles_legacy_metadata_without_asic_map` - Validates fallback behavior when `asic_to_interface` mapping is missing
- `test_generate_skeleton_port_info_handles_missing_intf_status` - Validates graceful handling of missing interface status data

**Key Features:**
- Uses `--noconftest` isolation to test fixtures in pure unit context
- Mocks dependencies for predictable, reproducible tests
- Validates infrastructure robustness against incomplete testbed metadata

## Important Notes

### --noconftest Flag

Unit tests in this directory use the `--noconftest` flag to:
- Disable automatic pytest plugin discovery
- Avoid loading `conftest.py` at the test level
- Provide pure unit test isolation without infrastructure dependencies

This is critical for testing `conftest.py` itself, as loading it as a pytest plugin would cause circular dependencies.

### Adding New Unit Tests

When adding new unit tests:
1. Place test files in `tests/unit_tests/`
2. Name files with `unit_test_` prefix
3. Use `--noconftest` when running to maintain isolation
4. Mock all external dependencies (fixtures, services, etc.)
5. Test single functions or components in isolation
6. Include docstrings explaining what is being tested

### Debugging

To debug a failing unit test with more verbose output:
```bash
python3 -m pytest --noconftest unit_tests/unit_test_conftest.py -vv -s --tb=long
```

- `-vv`: Extra verbose output
- `-s`: Show print statements
- `--tb=long`: Full traceback

## Related Documentation

- [Main Test Infrastructure](../README.md)
- [Fixtures Documentation](../common/fixtures/README.md) (if exists)
- [Snappi Tests](../common/snappi_tests/README.md) (if exists)
