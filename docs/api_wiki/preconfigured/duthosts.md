# duthosts

- [Overview](#overview)
- [Examples](#example)
- [Expected Output](#expected-output)

## Overview
Provides a dictionary that maps DUT hostnames to DUT instances

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
```

## Expected Output
A dictionary mapping hostnames to instances.