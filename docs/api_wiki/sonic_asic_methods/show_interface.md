# show_interface

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Show status and counter values for a given interface on the ASIC.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname, tbinfo, enum_frontend_asic_index):
    duthost = duthosts[rand_one_dut_hostname]

    sonic_asic = duthost.asic_instance(asic_index=enum_frontend_asic_index)

    bgp_info = sonic_asic.bgp_facts()
```

## Arguments
- `command` - Whether interface statuses or counters are desired
    - Required: `True`
    - Type: `String`
    - Choices:
        - `status`
        - `counter`
- `interfaces` - List of interface for facts to be gathered. If not defined facts are gathered for all interfaces
    - Required: `False`
    - Type: `List`
        - Element-Type: `String`
    - Default: `None`
- `namespace` - shows external interfaces for a specific ASIC's namespace
    - Required: `False`
    - Type: `String`
    - Default: `None`
- `include_internal_intfs` - Whether or not to include internal interfaces
    - Required: `False`
    - Type: `Boolean`
    - Default: `False`

## Expected Output
See the [show_interface](../ansible_methods/show_interface.md#expected-output) ansible module for expected output.