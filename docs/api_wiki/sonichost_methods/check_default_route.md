# check_default_route

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Provides the status of the default route

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    ipv4_route_status = duthost.check_default_route(ipv6=False)
```

## Arguments
- `ipv4` - Whether or not to check ipv4 route
    - Required: `False`
    - Type: `Boolean`
    - Default: `True`
- `ipv6` - Whether or not to check ipv6 route
    - Required: `False`
    - Type: `Boolean`
    - Default: `True`

## Expected Output
`True` if default route is accesible, `False` otherwise.