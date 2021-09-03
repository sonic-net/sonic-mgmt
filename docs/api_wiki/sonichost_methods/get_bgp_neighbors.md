# get_bgp_neighbors

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)


## Overview
This command provides a summary of the bgp neighbors peered with the DUT. Returns a dictionary that maps the BGP address for each neighbor to another dictionary listing information on that neighbor device.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    bgp_info = duthost.get_bgp_neighbors()
```

## Arguments

This command takes no arguments

## Expected Output
This command returns a dictionary mapping the neigbor's BGP address to another dictionary describing the neighbor device. The dictionary hierarchy is described below, with each indentation describing a sub-dictionary:

- `{bgp-ip}` - dictionary with information on the neihboring device matching the provided BGP ip
    - `remote AS` - ASN defined for the peer group
    - `local AS` - Local ASN for neighbor
    - `description` - The name of the BGP neighbor
    - `admin` - Admin status for interface used to communicate with neighbor
    - `accepted prefixes` - Number of accepted prefixes for that BGP neigbhor
    - `connections established` - number of connections established by BGP neighbor
    - `connections dropped` - number of connections dropped by neighbor
    - `peer group` - Name of peer group
    - `state` - Current state of BGP neighbor
    - `remote routerid` - remote router id on neighbor
    - `mrai` - Minimum Route Advertisement Interval
    - `ip_version` - version of IP used for communication with neighbor
    - `message statistics` - Dictionary describing statistics on communication with neighbor
        - `Capability`
            - `rcvd` - Capability messages received
            - `sent` - Capability messages sent
        - `Notifications`
            - `rcvd` - Notification messages received
            - `sent` - Notification messages sent
        - `Route Refresh`
            - `rcvd` - Route Refresh messages received
            - `sent` - Route Refresh messages sent
        - `Updates`
            - `rcvd` - Update messages received
            - `sent` - Update messages sent
        - `Keepalives`
            - `rcvd` - Keepalive messages received
            - `sent` - Keepalive messages sent
        - `Opens`
            - `rcvd` - Open messages received
            - `sent` - Open messages sent
        - `Total`
            - `rcvd` - total messages received
            - `sent` - total messages sent
