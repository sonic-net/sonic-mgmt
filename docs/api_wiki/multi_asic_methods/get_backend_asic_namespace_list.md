# get_backend_asic_namespace_list

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Provides list of namespaces for each ASIC on the Multi-ASIC device.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    backend_asic_ns = duthost.get_backend_asic_namespace_list()
```

## Arguments
Takes no arguments

## Expected Output
List of namespaces, one for each backend ASIC on the Multi-ASIC device.