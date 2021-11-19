# get_route

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Retreives BGP routes on a provided an ip prefix that the route must match.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    bgp_route = duthost.get_route("172.16.10.0/24")
```

## Arguments
- `prefix` - prefix used to select routes
    - Required: `True`
    - Type: `String`
- `namespace` - Namespace associated with desired ASIC
    - Required `False`
    - Type: `String`
    - Defalut: `None`

## Expected Output

# TODO