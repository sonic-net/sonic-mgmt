# shutdown_multiple

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Shuts down multiple specified interfaces.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    ret_code = duthost.shutdown_multiple(["Ethernet0", "Ethernet4", "Ethernet14"])
```

## Arguments
- `ifnames` - list of interface names corresponding the interfaces that should be shut down
    - Required: `True`
    - Type: `List`
        - Element-Type: `String`

## Expected Output
Returns return code for the `config` command.