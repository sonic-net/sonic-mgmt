# acl_facts

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Retrieves ACL information from remote host.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    acl_facts = duthost.acl_facts()
```

## Arguments
This method takes no arguments.

## Expected Output
A dictionary is returned containing information on the configured ACLs. The dictionary hierarchy is described below, with each indentation describing a sub-dictionary:

- `ansible_facts` - dictionary containing facts on ACL
    - `ansible_acl_facts` - Dictionary mapping ACL tables to their configurations
        - `{ACL_TABLE_NAME}` - Dictionary containing information on provided table
            - `policy_desc` - Description of the table policy
            - `ports` - List of the ports attached to the ACL table
            - `type` - type of ACL table (e.g. `L2` or `CTRLPLANE`)
            - `rules` - Dictionary that maps a rule name to its configuration
                - `{RULE_NAME}` - dictionary that maps a property of the rule to its value
                    - `ETHER_TYPE` - Ethernet type
                    - `PACKET_ACTION` - Whether to `DROP` or `FORWARD` a packet
                    - `PRIORITY` - Rule priority
                    - `bytes_count` - bytes affected by this rule
                    - `packets_count` - packets affected by this rule
                    - `SRC_IP` - IP that the packet is coming from
                    - `DST_IP` - IP that the packet is going to
                    - *There may be more key-value pairs than listed here
