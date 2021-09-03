# asics

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

`property`

## Overview
Get list of ASIC hosts

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    asics = duthost.asics
```

## Arguments
This method takes no arguments

## Expected Output
List of ASIC hosts.