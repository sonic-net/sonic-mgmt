# get_active_ip_interfaces

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Provides a information on active IP interfaces. Works on ASIC devices.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname, enum_frontend_asic_index):
    duthost = duthosts[rand_one_dut_hostname]

    sonic_asic = duthost.asic_instance(asic_index=enum_frontend_asic_index)

    active_intf_facts = sonic_asic.get_active_ip_interfaces()
```

## Arguments
This method takes no arguments

## Expected Output
Returns a list that contains dictionaries for each group of ip interfaces. The dictionary hierarchy is described below, with each indentation describing a sub-dictionary:
- `{INTERFACE_NAME}` - Dictionary that describes the interface
    - `bgp_neighbor` - name of connected neighbor
    - `ipv4` - configured interface ip
    - `peer_ipv4` - ip configured for bgp peer