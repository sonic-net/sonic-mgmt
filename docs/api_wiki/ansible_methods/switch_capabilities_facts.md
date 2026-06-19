# switch_capabilities_facts

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Retreive switch capability information.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    switch_capabilities = duthost.switch_capabilities_facts()
```

## Arguments
This method takes no arguments.

## Expected Output
Returns dictionary with data on capabilities of switch. The dictionary hierarchy is described below, with each indentation describing a sub-dictionary:

- `ansible_facts`
    - `switch-capabilities`
        - `switch` - Dictionary with data on switch capabilities.
            - `MAX_NEXTHOP_GROUP_COUNT` - maximum number of nexthop groups
            - `LAG_TPID_CAPABLE` - Boolean value representing whether switch is capable of LAG TPID
            - `ACL_ACTION|INGRESS` - String listing Ingress ACL actions (comma separated)
            - `ACL_ACTIONS|EGRESS` - String listing Egress ACL actions (comma separated)
            - `PORT_TPID_CAPABLE` - Boolean value representing whether switch is capable of PORT TPID
            - `MIRRORV6` - Whether ipv6 mirroring is enabled
            - `MIRROR` - Whether ipv4 mirroring is enabled
            - `ACL_ACTION|PACKET_ACTION` - String listing packet actions for acls (comma separated)
            - `ACL_ACTION|FLOW_OP` - String listing Flow operations for acls (comma separated)
