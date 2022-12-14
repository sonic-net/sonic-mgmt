# get_interfaces_status

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Get interfaces status on the DUT and parse the result into a dict.

## Examples
```python
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    images = duthost.get_interfaces_status()
```

## Arguments
This function takes no arguments.

## Expected Output
Returns dicitonary with the DUT interfaces status.

Example output:

```json
{
    "Ethernet0": {
        "oper": "down",
        "lanes": "25,26,27,28",
        "fec": "N/A",
        "asym pfc": "off",
        "admin": "down",
        "type": "N/A",
        "vlan": "routed",
        "mtu": "9100",
        "alias": "fortyGigE0/0",
        "interface": "Ethernet0",
        "speed": "40G"
    },
    "PortChannel101": {
        "oper": "up",
        "lanes": "N/A",
        "fec": "N/A",
        "asym pfc": "N/A",
        "admin": "up",
        "type": "N/A",
        "vlan": "routed",
        "mtu": "9100",
        "alias": "N/A",
        "interface": "PortChannel101",
        "speed": "40G"
    }
}
```
