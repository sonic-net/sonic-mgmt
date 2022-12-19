# ptfhost

- [Overview](#overview)
- [Examples](#example)
- [Expected Output](#expected-output)

## Overview
The PTF container host instance. Used to run ptf methods and anisble modules from the PTF.

## Examples
```
def test_fun(ptfhost):
    ptfhost.api_call()
```

## Expected Output
Ansible Host instance for PTF.