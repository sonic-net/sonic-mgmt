# sysfs_facts

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Get sysfs information from switch

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    facts = duthost.sysfs_facts(config={CONFIG_LIST})
```

## Arguments
- `config` - list of check items
    - Required: `True`
    - Type: `List`
        - Element-Type: `Dictionary`

## Expected Output

## TODO
Was not able to run on local machine.