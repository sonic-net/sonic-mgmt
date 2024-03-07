# show_ipv6_interface

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Retrieve ipv6 address of interface and ipv6 address for corresponding neighbor

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    ip_intfs = duthost.show_ipv6_interface()
```

## Arguments
- `namespace` - if multi-asic, namespace to run the commmand
    - Required: `False`
    - Type: `String`

## Expected Output
Provides a dictionary with information on the interfaces. The dictionary hierarchy is described below, with each indentation describing a sub-dictionary:

- `ansible_facts`
    - `ipv6_interfaces` - Dictionary mapping interface name to information on the interface
        - `{INTERFACE_NAME}` - Dictionary with info in interface
            - `bgp_neighbor` - Name of BGP neighbor for interface
            - `ipv6` - interface configured ipv6 address
            - `peer_ipv6` - BGP neighbor ipv6 address
            - `admin` - admin state
            - `oper_state` - operator state
            - `prefix_len` - interface prefix length
