# config_portchannel

# config_portchannel

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Creates or removes a portchannel on the ASIC instance

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname, enum_frontend_asic_index):
    duthost = duthosts[rand_one_dut_hostname]

    sonic_asic = duthost.asic_instance(asic_index=enum_frontend_asic_index)

    output = sonic_asic.config_portchannel("PortChannel0001", "del")
```

## Arguments
- `pc_name` - name of portchannel to be configured
    - Required: `True`
    - Type: `String`
- `op` - operation to be performed on the portchannel
    - Required: `True`
    - Type: `String`
    - Choices:
        - `add` - adds a portchannel with name `pc_name` to the ASIC instance.
        - `del` - removes portchannel with name `pc_name` from the ASIC instance.

## Expected Output
See the [shell](../ansible_methods/shell.md#expected-output) Ansible module for example output.