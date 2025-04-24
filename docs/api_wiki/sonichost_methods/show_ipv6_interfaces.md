# show_ipv6_interfaces

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Retrieve information about IPv6 interfaces and parse the result into a dict.

## Examples
```python
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    ipv6_ifs = duthost.show_ipv6_interfaces()
```

## Arguments
This function takes no arguments.

## Expected Output
Returns a dictionary containing information about the DUT's IPv6 interfaces.
Note: The result does NOT contain link-local IPv6 addresses.

Example output:

```json
{
    "Ethernet16": {
        "master": "Bridge",
        "ipv6 address/mask": "fe80::2048:23ff:fe27:33d8%Ethernet16/64",
        "admin": "up",
        "oper": "up",
        "bgp neighbor": "N/A",
        "neighbor ip": "N/A"
    },
    "PortChannel101": {
        "master": "",
        "ipv6 address/mask": "fc00::71/126",
        "admin": "up",
        "oper": "up",
        "bgp neighbor": "ARISTA01T1",
        "neighbor ip": "fc00::72"
    },
    "eth5": {
        "master": "",
        "ipv6 address/mask": "fe80::5054:ff:fee6:bea6%eth5/64",
        "admin": "up",
        "oper": "up",
        "bgp neighbor": "N/A",
        "neighbor ip": "N/A"
    }
}
```
