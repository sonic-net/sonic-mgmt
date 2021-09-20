# interface_facts

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Retrieves information on device interfaces.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    intf_facts = duthost.interface_facts()
```

## Arguments
- `up_ports` - All ports expected to be at link up status
    - Required: `False`
    - Type: `List`
        - Element-Type: `String`

## Expected Output
Returns a dictionary with information on interfaces. The dictionary hierarchy is described below, with each indentation describing a sub-dictionary:

- `ansible_facts`
    - `ansible_interface_link_down_ports` - List of interfaces with down ports
    - `anisble_interface_ips` - Dictionary with information on interface ips
        - `all_ipv6_addresses` - list of ipv6 addresses attached to interfaces
        - `all_ipv4_addresses` - list of ipv4 addresses attached to interfaces
    - `ansible_interface_facts` - Dictionary with information on each interface
        - `{INTERFACE_NAME}` - Dictionary with information on specified interface
            - `macaddress` - interface mac address
            - `mtu`
            - `device` - name of device, same as provided before
            - `promisc`
            - `link`
            - `ipv6` - List of dictionaries with information on connected ipv6 addresses
                - `address` - ipv6 address
                - `scope`
                - `prefix` - address prefix
            - `active` - Whether or not interface is active
            - `type` - type of interface