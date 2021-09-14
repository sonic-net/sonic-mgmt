# bgp_drop_rule

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Programs iptable rule to either add or remove DROP for BGP control frames

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname, tbinfo, enum_frontend_asic_index):
    duthost = duthosts[rand_one_dut_hostname]

    sonic_asic = duthost.asic_instance(asic_index=enum_frontend_asic_index)

    sonic_asic.bgp_drop_rule("IPv4", state="absent")
```

## Arguments
- `ip_version` - Whether protocol version 4 or 6 is being used
    - Required: `True`
    - Type: `String`
    - Choices:
        - `IPv4`
        - `IPv6`
- `state` - Whether to remove or add DROP rule
    - Required: `False`
    - Type: `String`
    - Default: `present`
    - Choices:
        - `present` - adds the rule or keeps it present
        - `absent` - removes the rule or does nothing if it was not there

## Expected Output
Provides no output.