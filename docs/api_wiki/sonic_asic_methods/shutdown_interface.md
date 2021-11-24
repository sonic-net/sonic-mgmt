# shutdown_interface

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Shuts down interface specified for the ASIC instance calling the method.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname, enum_frontend_asic_index):
    duthost = duthosts[rand_one_dut_hostname]

    sonic_asic = duthost.asic_instance(asic_index=enum_frontend_asic_index)

    output = sonic_asic.shutdown_interface("Ethernet0")
```

## Arguments
- `interface_name` - Name of interfaec to shut down
    - Required: `True`
    - Type: `String`

## Expected Output
See the [shell](../ansible_methods/shell.md#expected-output) Ansible module for example output.