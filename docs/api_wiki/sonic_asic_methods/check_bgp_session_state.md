# check_bgp_session_state

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Checks that the BGP statistic matches some expected value.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname, enum_frontend_asic_index):
    duthost = duthosts[rand_one_dut_hostname]

    sonic_asic = duthost.asic_instance(asic_index=enum_frontend_asic_index)

    asic_bgp_info = asic.check_bgp_session_state(neigh_ips, state)
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
