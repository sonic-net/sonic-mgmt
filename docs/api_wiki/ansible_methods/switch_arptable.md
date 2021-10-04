# switch_arptable

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Reterives ARP table from the SONiC switch

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    arptable = duthost.switch_arptable()
```

## Arguments
This function takes no arguments

## Expected Output
Returns a dictionary that describes the contents of the ARP table. The dictionary hierarchy is described below, with each indentation describing a sub-dictionary:

- `asnible_facts` - dictionary that contains arptable info
    - `aprtable` - dictionary that contains arptable info for ipv4 and ipv6
        - `v4` - dictionary that contains info on ipv4 arptable entries
            - `{IPV4_ADDRESS}` - dictionary containing information on entry associated with provided address
                - `interface` - name of interface associated with address
                - `macaddress` - macaddress for entry
                - `state` - state of interface
        - `v6` - dictionary that contains info on ipv6 arptable entries
            - `{IPV6_ADDRESS}` - dictionary containing information on entry associated with provided address
                - `interface` - name of interface associated with address
                - `macaddress` - macaddress for entry
                - `state` - state of interface