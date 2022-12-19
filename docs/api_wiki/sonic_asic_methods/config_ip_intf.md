# config_ip_intf

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Allows for addition or removal of ip addresses to existing interfaces on the ASIC instance.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname, enum_frontend_asic_index):
    duthost = duthosts[rand_one_dut_hostname]

    sonic_asic = duthost.asic_instance(asic_index=enum_frontend_asic_index)

    output = sonic_asic.config_ip_intf("Ethernet0", "10.0.0.1", "add")
```

## Arguments
- `interface_name` - interface to be configured
    - Required: `True`
    - Type: `String`
- `ip_address` - IP address to add or remove from the interface
    - Required: `True`
    - Type: `String`
- `op` - operation to perform
    - Required: `True`
    - Type: `String`
    - Choices:
        - `add` - add `ip_address` to interface
        - `remove`- remove `ip_adress` from interface

## Expected Output
See the [shell](../ansible_methods/shell.md#expected-output) Ansible module for example output.