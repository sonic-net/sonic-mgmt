# get_ip_route_info

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Returns route information for a destionation. The destination could an ip address or ip prefix.

## Examples

```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    route_info = duthost.get_ip_route_info(ipaddress.ip_address(unicode("192.168.8.0")))
```
## Arguments
- `destip` - destination for route info, could be ip address or ip prefix
    - Required: `True`
    - Type: `String`
- `ns` - desired namespace in case of multi-ASIC device
    - Required: `False`
    - Type: `String`
    - Default: `""`

## Expected Output
Returns dictionary with information on route. The dictionary hierarchy is described below, with each indentation describing a sub-dictionary:

- `set_src` - provided destination for route info
- `nexthops` - List of tuples describing nexthops. First item is the IP address, Second item is the interface.