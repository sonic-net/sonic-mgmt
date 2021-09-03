# sonic_pfc_counters

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Get or clear PFC counter for a device

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    counter_facts = duthost.sonic_pfc_counters(method="get")
```

## Arguments
- `method` - Whether to get or clear counters
    - Required: `True`
    - Type: `String`
    - Chocies:
        - `get`
        - `clear`

## Expected Output
Returns dictionary with information on interfaces and their counters. The dictionary hierarchy is described below, with each indentation describing a sub-dictionary:

- `ansible_facts`
    - `{INTERFACE_NAME}` - Dictionary with counters for specified interface
        - `Rx` - list of counters for recieved packets
        - `Tx` - list of counters for transmitted packets