# no_shutdown

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Starts up a specied interface.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    ret_code = duthost.no_shutdown("Ethernet0")
```

## Arguments
- `ifname` - name of interface to startup
    - Required: `True`
    - Type: `String`

## Expected Output
Returns return code for `config` command