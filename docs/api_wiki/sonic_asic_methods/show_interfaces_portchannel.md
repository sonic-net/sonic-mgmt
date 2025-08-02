# show_interfaces_portchannel

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Retrieve information about PortChannel interfaces and parse the result into a dict.

## Examples
```python
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    portchannel_ifs = duthost.show_interfaces_portchannel()
```

## Arguments
This function takes no arguments.

## Expected Output
Returns a dictionary containing information about the DUT's PortChannel interfaces.
Note: The returned dictionary does not include protocol and port flags.

Example output:

```json
{
    "PortChannel101": {
        "protocol": "LACP",
        "ports": ["Ethernet0"]
    },
    "PortChannel102": {
        "protocol": "LACP",
        "ports": ["Ethernet20", "Ethernet40"]
    },
    "PortChannel103": {
        "protocol": "LACP",
        "ports": ["Ethernet68", "Ethernet72", "Ethernet76"]
    },
    "PortChannel104": {
        "protocol": "LACP",
        "ports": ["Ethernet80"]
    }
}
```
