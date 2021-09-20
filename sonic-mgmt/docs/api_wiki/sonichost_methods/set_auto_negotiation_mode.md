# set_auto_negotiation_mode

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Sets the auto negotiation mode for a provided interface

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    success = duthost.set_auto_negotiation_mode("Ethernet0", "True")
```

## Arguments
- `interface_name` - name of interface to set auto negotation for
    - Required: `True`
    - Type: `String`
- `mode` - Whether or not to enable auto negotation.
    - Required: `True`
    - Type: `Boolean`

## Expected Output
`False` if operation was not supported, else `True`