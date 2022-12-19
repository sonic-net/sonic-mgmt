# check_bgp_statistic

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

    stat_matches = sonic_asic.check_bgp_statistic("ipv4_idle", 1)
```

## Arguments
- `stat` - name of statistic to check for
    - Required: `True`
    - Type: `String`
    - Choices: for possible values look for keys under `bgp_statistics` in the output of the [bgp_facts](../ansible_methods/bgp_facts.md#expected-output) Ansible module.
- `value` - expected value that `stat` should match
    - Required: `True`
    - Type: Varies depending on `stat`

## Expected Output
`True` if BGP statistic associated with `stat` matches `value`, `False` otherwise.