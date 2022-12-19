# ping_v4

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Pings ipv4 address and provides result.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    ping_nbr = duthost.ping_v4("10.0.0.51", count=5)
```

## Arguments
- `ipv4` - ip address to ping
    - Required: `True`
    - Type: `String`
- `count` - Number of times to ping address
    - Required: `False`
    - Type: `Integer`
    - Default: `1`
- `ns_arg` - Namespace desried. In the case of multi-ASIC environments.
    - Required: `False`
    - Type: `String`
    - Default: `""`

## Expected Output
`True` if ping was successful, `False` otherwise.