# get_bgp_statistic

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Get the value corresponding to a named statistic for BGP.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname, enum_frontend_asic_index):
    duthost = duthosts[rand_one_dut_hostname]

    sonic_asic = duthost.asic_instance(asic_index=enum_frontend_asic_index)

    stat_name = sonic_asic.get_bgp_statistic("ipv4_idle")
```

## Arguments
- `stat` - name of statistic to get from BGP info.
    - Required: `True`
    - Type: `String`
    - Choices: for possible values look for keys under `bgp_statistics` in the output of the [bgp_facts](../ansible_methods/bgp_facts.md#expected-output) Ansible module.

## Expected Output
Returns whatever value is assigned the key `stat` provided.