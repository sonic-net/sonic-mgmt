# get_frontend_asic_namespace_list

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Provides list of all namespaces corresponding to ASICs on Multi-ASIC device.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    frontend_asics_ns = duthost.get_frontend_asic_namespace_list()
```

## Arguments
Takes no arguments

## Expected Output
Returns list of namespaces, one for each frontend ASIC on the Multi-ASIC device.