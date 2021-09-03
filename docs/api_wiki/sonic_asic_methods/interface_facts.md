# interface_facts

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Gets information about interfaces associated with the ASIC calling the method.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname, tbinfo, enum_frontend_asic_index):
    duthost = duthosts[rand_one_dut_hostname]

    sonic_asic = duthost.asic_instance(asic_index=enum_frontend_asic_index)

    intf_info = sonic_asic.interface_facts()
```

## Arguments
- `up_ports` - All ports expected to be at link up status
    - Required: `False`
    - Type: `List`
        - Element-Type: `String`

## Expected Output
See the [interface_facts](../ansible_methods/interface_facts.md#expected-output) Ansible module for example output.