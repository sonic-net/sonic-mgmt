# switch_arptable

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Gets ARP table information from sonichost device specified for ASIC instance calling the method.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname, enum_frontend_asic_index):
    duthost = duthosts[rand_one_dut_hostname]

    sonic_asic = duthost.asic_instance(asic_index=enum_frontend_asic_index)

    arp_info = sonic_asic(switch_arptable)
```

## Arguments
Takes no arguments.

## Expected Output
See the [switch_arptable](../ansible_methods/switch_arptable.md#expected-output) Ansible module for example output.