# get_namespace_from_asic_id

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Gets the namespace provided an ASIC ID. This only works on multi-ASIC devices.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    default_asic_namespace = duthost.get_namespace_from_asic_id(self, None)
```

## Arguments
- `asic_id` - Numeric ID for desired ASIC namespace. If `None` is provided, default ASIC namespace is returned.
    - Required: `True`
    - Type: `Integer`

## Expected Output
String representing the namespace associated with provided ID.