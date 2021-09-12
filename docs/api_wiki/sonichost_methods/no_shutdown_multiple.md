# no_shutdown_multiple

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Startup multiple interfaces.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    ret_code = duthost.no_shutdown_multiple(["Ethernet0", "Ethernet4", "Ethernet14"])
```

## Arguments
- `ifnames` - List of interface names corresponding to the interfaces that should be started up
    - Required: `True`
    - Type: `List`
        - Element-Type: `String`

## Expected Output
Returns return code for `config` command.