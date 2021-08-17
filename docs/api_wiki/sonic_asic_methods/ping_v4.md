# ping_v4

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Pings specified ipv4 address via ASIC.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname, tbinfo, enum_frontend_asic_index):
    duthost = duthosts[rand_one_dut_hostname]

    sonic_asic = duthost.asic_instance(asic_index=enum_frontend_asic_index)

    ping = sonic_asic.ping_v4(unicode("10.0.0.51"))
```

## Arguments
- `ipv4`
    - Required: `True`
    - Type: `unicode`
- `count`
    - Required: `False`
    - Type: `Integer`
    - Default: `1`

## Expected Output
`True` if ping was a success, `False` otherwise.