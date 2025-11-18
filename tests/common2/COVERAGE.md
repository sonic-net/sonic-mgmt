# Coverage Testing System

This directory contains a comprehensive coverage testing system for enforcing code quality standards across all Python modules.

## Features

- **Automatic Module Discovery**: Automatically detects all Python modules in the directory
- **Individual Module Coverage**: Checks coverage for each module separately
- **Configurable Thresholds**: Set minimum coverage requirements (default: 80%)
- **Coverage Enforcement**: Fails builds if coverage requirements aren't met
- **Multiple Output Formats**: Terminal and HTML coverage reports
- **CI/CD Integration**: Easy integration with continuous integration pipelines

## Available Commands

### Basic Testing
```bash
make test                    # Run unit tests
make test-verbose           # Run unit tests with verbose output
```

### Coverage Testing
```bash
make test-coverage          # Run tests with coverage report
make test-coverage-enforced # Run tests with coverage enforcement
make coverage-check         # Check coverage for each module
make coverage-enforce       # Enforce coverage requirements (CI-friendly)
make coverage-report        # Generate reports from existing coverage data
```

### Utility Commands
```bash
make list-modules           # List all modules that will be tested
make set-min-coverage       # Show how to change minimum coverage
make clean                  # Clean up test artifacts
make help                   # Show all available commands
```

## Configuration

### Minimum Coverage Threshold
Change the minimum coverage requirement for any command:
```bash
make test-coverage-enforced MIN_COVERAGE=85
make coverage-check MIN_COVERAGE=90
```

The default minimum coverage is **80%**.

### Module Selection
The system automatically discovers Python modules but excludes:
- Files starting with underscore (`_*.py`)
- Utility scripts (`check_coverage.py`, `setup.py`, `conftest.py`)
- Test files in `unit_tests/` directory

## Coverage Reports

### Terminal Report
Shows coverage for each module with pass/fail status:
```
Coverage Report (minimum: 80.0%)
==================================================
bgp_route_control           95.0%  ✅ PASS
other_module                85.0%  ✅ PASS
new_module                  75.0%  ❌ FAIL
==================================================
```

### HTML Report
Generated in `htmlcov/` directory with detailed line-by-line coverage information.

## CI/CD Integration

### GitHub Actions / Azure Pipelines
```yaml
- name: Run tests with coverage enforcement
  run: |
    cd tests/common2
    make test-coverage-enforced
    make coverage-enforce
```

### Pre-commit Hook
Add to `.pre-commit-config.yaml`:
```yaml
- repo: local
  hooks:
    - id: coverage-check
      name: Coverage Check
      entry: make -C tests/common2 coverage-enforce
      language: system
      pass_filenames: false
```

## Adding New Modules

1. **Create your module**: Add a new `.py` file in `tests/common2/`
2. **Write unit tests**: Add corresponding tests in `unit_tests/test_*.py`
3. **Run coverage check**: `make test-coverage-enforced`
4. **Ensure minimum coverage**: Add more tests if needed to reach 80%+ coverage

Example:
```bash
# After adding new_module.py and unit_tests/test_new_module.py
make test-coverage-enforced
make coverage-check
```

## Coverage Enforcement Levels

### 1. **Development** (Permissive)
```bash
make test-coverage          # Shows coverage but doesn't fail
```

### 2. **CI/CD** (Enforced)
```bash
make test-coverage-enforced # Fails build if overall coverage < threshold
make coverage-enforce       # Fails if any individual module < threshold
```

### 3. **Release** (Strict)
```bash
make test-coverage-enforced MIN_COVERAGE=90
make coverage-enforce MIN_COVERAGE=90
```

## Troubleshooting

### "No modules found"
- Check that you have `.py` files in the current directory
- Ensure files don't start with underscore
- Run `make list-modules` to see what's detected

### "pytest-cov not installed"
```bash
pip install pytest-cov coverage
```

### Coverage too low
1. Check the detailed HTML report: `htmlcov/index.html`
2. Add more unit tests for uncovered lines
3. Remove unreachable code if appropriate

### Individual module failing
```bash
# Check specific module coverage
python3 check_coverage.py --modules your_module_name --min-coverage 80
```

## Best Practices

1. **Maintain High Coverage**: Aim for 85%+ coverage on all modules
2. **Test Edge Cases**: Cover error conditions and boundary cases
3. **Regular Monitoring**: Run coverage checks frequently during development
4. **Documentation**: Update tests when functionality changes
5. **CI Integration**: Always run coverage enforcement in CI/CD pipelines

## File Structure

```
tests/common2/
├── Makefile                    # Main coverage testing commands
├── check_coverage.py           # Coverage checking script
├── pytest.ini                 # Pytest configuration
├── unit_tests/                 # Unit test files
│   └── test_*.py
├── your_module.py              # Your Python modules
├── htmlcov/                    # HTML coverage reports
└── .coverage                   # Coverage data file
```

## Dependencies

- `pytest`: Testing framework
- `pytest-cov`: Coverage plugin for pytest
- `coverage`: Core coverage measurement tool

Install with:
```bash
pip install pytest pytest-cov coverage
```
