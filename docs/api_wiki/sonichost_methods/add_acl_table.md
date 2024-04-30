# add_acl_table

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Add new acl table via command `sudo config acl add table `

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    duthost.add_acl_table(table_name="Test_TABLE",
                          table_type="L3",
                          acl_stage="ingress",
                          bind_ports=["Ethernet0", "Ethernet1", "Ethernet3"])
```

## Arguments
 - `table_name` - table name of acl table
    - Required: `True`
    - Type: `String`
 - `table_type` - table type of acl table
    - Required: `True`
    - Type: `String`
 - `acl_stage` - acl stage
    - Required: `False`
    - Type: `String`
        - Validate value: "ingress" or "egress"
    - Default: None
 - `bind_ports` - ports to bind
    - Required: `False`
    - Type option 1: `String`
        - Format: Ethernet0,Ethernet1,Ethernet3
    - Type option 2: `List`
        - Member Type: `String`
        - Format: ["Ethernet0", "Ethernet1", "Ethernet3"] or ["Vlan100", "Vlan200"]
        - This list of interfaces will be join to a string
        - If list of VLAN name provided, acl table will bind to ports binding to those VLAN.
    - Default: None
 - `description` - description of acl table
    - Required: `False`
    - Type: `String`
    - Default: None

## Expected Output
None
