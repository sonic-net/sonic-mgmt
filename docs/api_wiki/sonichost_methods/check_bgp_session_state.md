# check_bgp_session_state

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Check whether the state of the bgp session matches a specified state for a list of bgp neighbors.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    bgp_info = duthost.get_bgp_session_state([unicode("10.0.0.51"), unicode("10.0.0.53")])
```

## Arguments
- `neigh_ips` - List of neighbor BGP IPs that are being checked against the `state` param
    - Required: `True`
    - Type: `List`
        - Element-Type: `unicode`
- `state` - What state the BGP sessions are expected to be in
    - Required: `False`
    - Type: `String`
    - Default: `established`

## Expected Output
`True` if all neighbors in `neigh_ips` match the `state` param, `False` otherwise