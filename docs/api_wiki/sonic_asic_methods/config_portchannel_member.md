# config_portchannel_member

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Adds or removes portchannel member for a specified portchannel on the ASIC instance.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname, enum_frontend_asic_index):
    duthost = duthosts[rand_one_dut_hostname]

    sonic_asic = duthost.asic_instance(asic_index=enum_frontend_asic_index)

    output = sonic_asic.config_portchannel_member("PortChannel0001", "Ethernet14", "add")
```

## Arguments
- `pc_name` - name of portchannel to modify
    - Required: `True`
    - Type: `String`
- `interface_name` - name of interface to add or remove from portchannel
    - Required: `True`
    - Type: `String`
- `op` - Operation to perform on member
    - Required: `True`
    - Type: `String`
    - Choices:
        - `add` - adds specified interface as member of portchannel
        - `del` - removes spcified interface member from portchannel

## Expected Output
See the [shell](../ansible_methods/shell.md#expected-output) Ansible module for example output.