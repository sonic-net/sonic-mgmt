# get_asic_id_from_namespace

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Returns numeric ID for ASIC given a namespace. This command only works if the dut is a multi-asic device.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    rand_namespace = duthost.get_asic_namespace_list()[0]

    asic_id = duthost.get_asic_id_from_namespace(rand_namespace)
```

## Arguments
- `namespace` - namespace that corresponds to desired ASIC ID
    - Required: `True`
    - Type: `String`

## Expected Output
The numeric ASIC ID corresponding to the provided namespace.