# localhost

- [Overview](#overview)
- [Examples](#example)
- [Expected Output](#expected-output)

## Overview
The localhost instance. Used to run ansible modules from the localhost.

## Examples
```
def test_fun(localhost):
    localhost.api_call()
```

## Expected Output
An Ansible Host instance capable of calling ansible modules.