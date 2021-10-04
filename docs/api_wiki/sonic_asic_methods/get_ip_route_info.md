# get_ip_route_info

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Returns route information for a destionation. The destination could an ip address or ip prefix.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname, tbinfo, enum_frontend_asic_index):
    duthost = duthosts[rand_one_dut_hostname]

    sonic_asic = duthost.asic_instance(asic_index=enum_frontend_asic_index)

    ip_route_info = sonic_asic.get_ip_route_info(ipaddress.ip_address(unicode("192.168.8.0")))
```

## Arguments
- `dstip` - destination ip. Could be address or prefix.
    - Required: `True`
    - Type: `String`

## Expected Output
Returns dictionary with information on route. The dictionary hierarchy is described below, with each indentation describing a sub-dictionary:

- `set_src` - provided destination for route info
- `nexthops` - List of tuples describing nexthops. First item is the IP address, Second item is the interface.