# bgp_facts

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Retreives BGP information using Quagga

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    bgp_facts = duthost.bgp_facts()
```

## Arguments
- `nump_npus` - number of network processing units
    - Required: `False`
    - Type: `Integer`
    - Default: `1`
- `instance_id` - ASIC instance id for desired ASIC (for multi-asic devies)
    - Required: `False`
    - Type: `Integer`

## Expected Output
Returns dictionary with information on BGP configuration. The dictionary hierarchy is described below, with each indentation describing a sub-dictionary:

- `ansible_facts`
    - `bgp_statistics` - Dictionary describing general BGP stats
        - `ipv4_idle` - Number of ipv4 BGP neighbors in an idle state
        - `ipv6_idle` - Number of ipv6 BGP neighbors in an idle state
        - `ipv4_admin_down` - Number of ipv4 BGP neighbors with a `down` admin state
        - `ipv6_admin_down` - Number of ipv6 BGP neighbors with a `down` admin state
        - `ipv4` - Number of ipv4 BGP neighbors
        - `ipv6` - Number of ipv6 neighbors
    - `bgp_neighbors` - Dictionary that maps BGP ip to information on neighbor
        - `{BGP_IP}` - Dictionary that provides information on specified neighbor
            - `remote AS` - neighbor's remote ASN
            - `description` - Neighbor name
            - `admin` - admin status
            - `accepted prefixes` - number of accepted prefixes
            - `message statistics` - Dictionary with statistics on messages send and received
                - `Capability`
                    - `rcvd` - Number of received capability messages
                    - `sent` - Number of sent capability messages
                - `Notifications`
                    - `rcvd` - Number of received notifications messages
                    - `sent` - Number of sent notifications messages
                - `Route Refresh`
                    - `rcvd` - Number of received route refresh messages
                    - `sent` - Number of sent route refresh messages
                - `Keepalives`
                    - `rcvd` - Number of received keepalive messages
                    - `sent` - Number of sent keepalive messages
                - `Opens`
                    - `rcvd` - Number of received open messages
                    - `sent` - Number of sent open messages
                - `Total`
                    - `rcvd` - Total number of received messages
                    - `sent` - Total number of messages sent
                - `capabilities` - Dictioanry mapping capability message to how many times it was sent
                    - `{CAPABILITY_MSG}` - number of times specified message was sent
                - `peer group` - name of peer group
                - `state` - state of BGP neighbor
                - `connections established` - Number of connections established by neighbor
                - `connections dropped` - Number of connections dropped by neighbor
                - `mrai` - Minimal route advertisement interval
                - `ip_version`: type of ip version for neighbor
                - `local AS`: local AS number
                - `remote routerid`