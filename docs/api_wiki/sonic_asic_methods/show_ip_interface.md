# show_ip_interface

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Retrieve ipv4 address for interface and ipv4 address for corresponding neighbor

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname, tbinfo, enum_frontend_asic_index):
    duthost = duthosts[rand_one_dut_hostname]

    sonic_asic = duthost.asic_instance(asic_index=enum_frontend_asic_index)

    ip_intf = sonic_asic.show_ip_interface()
```

## Arguments
- `namespace` - if multi-asic, namespace to run the commmand
    - Required: `False`
    - Type: `String`

## Expected Output
See the [show_ip_interface](../ansible_methods/show_ip_interface.md#expected-output) Ansible module for example output.