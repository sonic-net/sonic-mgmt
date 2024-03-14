# get_vlan_brief

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)
- [Potential Exception](#potential-exception)

## Overview

Read vlan brief information from running config.

## Examples

```python
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    vlan_brief = duthost.get_vlan_brief()
```

## Arguments

None

## Expected Output

Returns an dict, key is vlan name and value is brief information.

Example output:

```
{
    "Vlan1000": {
        "interface_ipv4": [ "192.168.0.1/24" ],
        "interface_ipv6": [ "fc02:1000::1/64" ],
        "members": ["Ethernet0", "Ethernet1"]
    },
    "Vlan2000": {
        "interface_ipv4": [ "192.168.1.1/24" ],
        "interface_ipv6": [ "fc02:1001::1/64" ],
        "members": ["Ethernet3", "Ethernet4"]
    }
}
```

## Potential Exception

- [Exception from function get_running_config_facts](get_running_config_facts.md)
