# get_asic_or_sonic_host

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Returns ASIC instance provided a corresponding ASIC instance id.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    asic = duthost.get_asic_id(DESIRED_ASIC_ID)
```

## Arguments
- `asic_id` - ID for ASIC desired. If `None` is used, the default ASIC is returned.
    - Required: `True`
    - Type: `Integer`


## Expected Output
ASIC instance corresponding to provided ID.