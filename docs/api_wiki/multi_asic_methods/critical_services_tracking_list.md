# critical_services_tracking_list

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Gets the list of services running on the DUT.

These include the services running on the sonichost as well as those that are replicated for each ASIC.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    crit_servs = duthost.critical_services_tracking_list()
```

## Arguments
Takes no arguments

## Expected Output
A list of all critical services running on DUT.