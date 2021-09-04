# get_facts

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Returns `facts` property. See [facts](facts).

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    facts = duthost.get_facts()
```

## Arguments
Takes no Arguments.

## Expected Output
See [facts](facts)