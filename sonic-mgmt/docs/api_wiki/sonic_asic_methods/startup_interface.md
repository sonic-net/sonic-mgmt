# startup_interface

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Starts up interface specified for ASIC instance calling the method.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname, enum_frontend_asic_index):
    duthost = duthosts[rand_one_dut_hostname]

    sonic_asic = duthost.asic_instance(asic_index=enum_frontend_asic_index)

    output = sonic_asic.startup_interface("Ethernet0")
```

## Arguments
- `interface_name` - name of interface to start up
    - Required: `True`
    - Type: `String`

## Expected Output
See the [shell](../ansible_methods/shell.md#expected-output) Ansible module for example output.