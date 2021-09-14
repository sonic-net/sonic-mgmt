# bgp_route

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Provides BGP routing info from Quagga using VTYSH cli.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname, tbinfo):
    duthost = duthosts[rand_one_dut_hostname]

    bgp_route_neigh = duthost.bgp_route(neighbor="10.0.0.59", direction="adv")
```

## Arguments

- `direction` - to restict retrieving bgp neighbor advertise or received routes
    - Required: `False`, unless `neighbor` argument is provided.
    - Choices: 
        - `adv` - Advertising
        - `rec` - Receiving
    - Type: `String`

- `neighbor` - restirct retrieving routing information from bgp neighbor. bgp neighbor address is expected to follow this option
    - Required: `False`
    - Default: `None`
    - Type: `String`

- `prefix` - bgp prefix to be retrieved from show ip bgp
    - Required: `False`
    - Default: `None`
    - Type: `String`

## Expected Output
Returns a dictionary containing information on the bgp route given the provided arguments.The dictionary hierarchy is described below, with each indentation describing a sub-dictionary:

- `ansible_facts` - Route map info
    - `bgp_route_neiadv` - BGP route information for advertised routes. Only present if `neighbor` and `direction='adv'` is specified.
        - `neighbor` - BGP IP for chosen neighbor
        - `{route-ip}` - IP for node in route table
            - `origin` - origin source for route `i` for Internal Gateway Protocol or `e` for External Gateway Protocol
            - `weigh` - tie breaker used to determine best path
            - `nexthop` - nexthop configured for neighbor
            - `aspath` - aspath configured for neighbor
        
