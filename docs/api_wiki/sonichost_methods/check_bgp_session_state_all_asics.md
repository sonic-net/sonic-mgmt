# check_bgp_session_state_all_asics

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

    bgp_info = duthost.get_bgp_neighbors_per_asic()
    bgp_match = duthost.check_bgp_session_state_all_asics(bgp_info, state)
```

## Arguments
- `bgp_neighbors` - Dictionary with List of neighbor BGP IPs that are being checked against the `state` param for each namespace.
    - Required: `True`
    - Type: `Dict`
- `state` - What state the BGP sessions are expected to be in
    - Required: `False`
    - Type: `String`
    - Default: `established`

## Expected Output
`True` if all neighbors in `bgp_neighbors` match the `state` param, `False` otherwise
