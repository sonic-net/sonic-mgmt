# get_speed

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Gets configured speed for a given interface.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    eth0_speed = duthost.get_speed("Ethernet0")
```

## Arguments
- `interface_name` - name of interface to get speed for
    - Required: `True`
    - Type: `String`

## Expected Output
Returns speed as `String` in `10G` format.