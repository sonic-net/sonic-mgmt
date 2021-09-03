# get_vlan_intfs

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Retrieves list of interfaces belonging to a VLAN.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    vlan_interfaces = duthost.get_vlan_intfs()
```

## Arguments
This method takes no arguments

## Expected Output
Method returns a list of interface names corresponding the the interfaces who belong to a VLAN. 