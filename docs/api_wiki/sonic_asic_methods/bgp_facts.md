# bgp_facts

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Provides BGP facts for current ASIC.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname, enum_frontend_asic_index):
    duthost = duthosts[rand_one_dut_hostname]

    sonic_asic = duthost.asic_instance(asic_index=enum_frontend_asic_index)

    bgp_info = sonic_asic.bgp_facts()
```

## Arguments
- `nump_npus` - number of network processing units
    - Required: `False`
    - Type: `Integer`
    - Default: `1`
- `instance_id` - ASIC instance id for desired ASIC (for multi-asic devies)
    - Required: `False`
    - Type: `Integer`
    
## Expected Output
See the [bgp_facts](../ansible_methods/bgp_facts.md#expected-output) Ansible module for example output.