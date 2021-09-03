# active_ip_interfaces

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Provides information on all active IP (Ethernet or Portchannel) interfaces given a list of interface names.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    ip_ifaces = duthost.active_ip_interfaces(["Ethernet0", "Ethernet14", "PortChannel0001", "PortChannel0004"])
```

## Arguments
- `ip_ifs` - list of interfaces to check for `up` status
    - Required: `True`
    - Type: `List`
        - Element-Type: `String`
- `ns_arg` - Namespace desired. For multi-ASIC environments.
    - Required: `False`
    - Type: `String`
    - Default: `""`

## Expected Output
Returns a dictionary with information on the active interfaces.The dictionary hierarchy is described below, with each indentation describing a sub-dictionary:

- `{INTERFACE_NAME}` - Dictionary with information on specified interface
    - `ipv4` - ipv4 address attached to interface
    - `peer_ipv4` - ipv4 address of peer corresponding to interface
    - `bgp_neighbor` - name of bgp neighbor corresponding to interface