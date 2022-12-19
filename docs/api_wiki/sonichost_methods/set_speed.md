# set_speed

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Sets speed for desired interface.

If auto negotiation mode is enabled, this method sets the advertised speeds. Otherwise, the force speed is set.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    success = duthost.set_speed("Ethernet0", "10G")
```

## Arguments
- `interface_name` - name of interface to set speed for
    - Required: `True`
    - Type: `String`
- `speed` - speed to set interface
    - Required: `True`
    - Type: `String`
    - Format: `10G` = 10 gigabytes, `100G` = 100 Gigabytes, etc...

## Expected Output
`True` if command succeeds, `False` otherwise