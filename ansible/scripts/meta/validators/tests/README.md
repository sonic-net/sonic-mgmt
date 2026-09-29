# Meta Validator Unit Tests

This directory contains unit tests for validators under ansible/scripts/meta/validators.

## Current tests

- unit_test_console_validator.py

## What is covered

The console validator unit test currently validates:

- Building BMC-host pairs from testbed data using the duts field.
- Building BMC-host pairs from testbed data using the dut fallback field.

## Run locally

From the repository root:

```bash
python -m pytest -q ansible/scripts/meta/validators/tests/unit_test_console_validator.py
```

## Run in sonic-mgmt container

Example:

```bash
cd /var/src/sonic-mgmt-int
python3 -m pytest -q ansible/scripts/meta/validators/tests/unit_test_console_validator.py
```
