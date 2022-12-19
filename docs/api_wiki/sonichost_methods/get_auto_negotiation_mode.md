# get_auto_negotiation_mode

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Gets the auto negotiation status for a provided interface

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    eth0_auto_neg = duthost.get_auto_negotiation_mode("Ethernet0")
```

## Arguments
- `interface_name` - name of interface
    - Required: `True`
    - Type: `String`

## Expected Output
`True` if auto-negotiation is on, `False` otherwise. Returns `None` is auto negotiation is not compatible with interface.