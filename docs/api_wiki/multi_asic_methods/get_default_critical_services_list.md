# get_default_critical_services_list

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Provides the default list of critical services for Multi-ASIC device.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    def_crit_servs = duthost.get_default_critical_services()
```

## Arguments
Takes no arguments

## Expected Output
List of services that are considered critical services by default.