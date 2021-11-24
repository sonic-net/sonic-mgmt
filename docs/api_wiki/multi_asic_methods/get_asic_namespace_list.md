# get_asic_namespace_list

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Provides list of namspaces corresponding to ASICs on the duthost. The dut must be a multi-ASIC device for this method to work.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    namespace_list = duthost.get_asic_namespace_list()
```

## Arguments
Takes no arguments.

## Expected Output
List of namespaces corresponding to each asic on the dut device.