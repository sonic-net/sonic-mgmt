# Quick Start: Running Sample Tests

## The Solution: Use `--rootdir=.`

The key is to run pytest with `--rootdir=.` from within the sample_tests/ directory:

```bash
cd /path/to/sonic-mgmt-1/tests/common/plugins/conditional_mark/sample_tests

# Option 1: Run the provided script (recommended)
./run_sample_tests.sh

# Option 2: Run tests manually
python -m pytest --rootdir=. test_backward_compat.py -v

# Option 3: Run all sample tests
python -m pytest --rootdir=. . -v
```

## Why `--rootdir=.` is Needed

Pytest automatically loads `conftest.py` files from parent directories. The main `tests/conftest.py` has heavy dependencies (scapy, ansible modules, etc.). Using `--rootdir=.` tells pytest to only look in the current directory.

## Testing the Category Feature

```bash
cd sample_tests/

# Verify implementation is correct
./test_implementation.sh

# Run sample tests
./run_sample_tests.sh

# Or run specific tests
python -m pytest --rootdir=. test_category_permanent.py -v
python -m pytest --rootdir=. test_category_temporary.py -v
```

## If You Have Full sonic-mgmt Environment

If you have all dependencies installed and a configured testbed, you can run from anywhere:

```bash
cd /path/to/sonic-mgmt-1/tests

pytest common/plugins/conditional_mark/sample_tests/ \
    --mark-conditions-files common/plugins/conditional_mark/sample_tests/sample_mark_conditions.yaml \
    --testbed <your-testbed> \
    --testbed_file <your-testbed-file> \
    --inventory ../ansible/<your-inventory> \
    -v
```

## Quick Summary

✅ **Works:** `cd sample_tests && python -m pytest --rootdir=. . -v`
❌ **Fails:** `python -m pytest tests/common/plugins/.../sample_tests/ -v` (loads parent conftest)
