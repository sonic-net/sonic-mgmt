# get_frontend_asic_ids

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Provides a list of ASIC indexes representing the ASICs on the device.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    frontend_asics = duthost.get_frontend_asic_ids()
```

## Arguments
Takes no arguments

## Expected Output
Returns a list of asic indexes, one for each frontend ASIC on the multi-ASIC device.