# get_intf_link_local_ipv6_addr

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Get the link local ipv6 address of the interface

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    duthost.get_intf_link_local_ipv6_addr("Ethernet0")
```

## Arguments
 - `intf` - the interface name
    - Required: `True`
    - Type: `String`

## Expected Output
Link local only IPv6 address like: fe80::2edd:e9ff:fefc:dd58 or empty string if not found.
