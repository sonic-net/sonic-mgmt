# get_crm_resources

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Gets information on CRM resources from host

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    crm_resc = duthost.crm_resources()
```

## Arguments
This method takes no arguments

## Expected Output
Dictionary with information on CRM resources.The dictionary hierarchy is described below, with each indentation describing a sub-dictionary:

- `main_resources` - Information on main resources
    - `ipv6_nexthop`
        - `available`
        - `used`
    - `ipv6_neighbor`
        - `available`
        - `used`
    - `ipv4_neighbor`
        - `available`
        - `used`
    - `impc_entry`
        - `available`
        - `used`
    - `ipv4_route`
        - `available`
        - `used`
    - `snat_entry`
        - `available`
        - `used`
    - `dnat_entry`
        - `available`
        - `used`
    - `fdb_entry`
        - `available`
        - `used`
    - `ipv6_route`
        - `available`
        - `used`
    - `ipv4_nexthop`
        - `available`
        - `used`
    - `nexthop_group`
        - `available`
        - `used`
- `table_resources`
- `acl_resources` - List of dictionaries, each corresponding to a different resource
    - `bind_point`
    - `resource_name`
    - `used_count`
    - `available_count`
    - `stage` - `INGRESS` or `EGRESS`