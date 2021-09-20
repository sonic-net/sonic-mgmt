# facts

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

`property`

## Overview
Returns platform information facts about the sonic device.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    platform_facts = duthost.facts
```

## Arguments
Takes no arguments.

## Expected Output
Provides dictionary with platform info:

`platform` - name of platform
`hwksu` - Hardware switch being used
`asic_type` - Type of asic
`num_asic` - Number of asics
`router_mac` - router's mac address