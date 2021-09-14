# get_supported_speeds

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Gets a list of all supported speeds for a given interface.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    supported_speeds = duthost.get_supported_speeds("Ethernet0")
```

## Arguments
- `interface_name` - name of interface to get supported speeds for
    - Required: `True`
    - Type: `String`

## Expected Output
List of supported speeds where each speed is represented by a string.