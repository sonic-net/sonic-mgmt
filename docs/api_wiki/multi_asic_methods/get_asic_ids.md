# get_asic_ids

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Provides all ASIC indexes for the ASICs on the Multi-ASIC device.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    all_asic_ids = duthost.get_asic_ids()
```

## Arguments
Takes no arguments

## Expected Output
List of ASIC indexes, one for each ASIC on the Multi-ASIC device