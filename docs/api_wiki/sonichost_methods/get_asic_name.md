# get_asic_name

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Returns name of current ASIC. For use in multi-ASIC environments.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    asic_name = duthost.get_asic_name()
```

## Arguments
Takes no arguments

## Expected Output
Returns name of ASIC as a string.