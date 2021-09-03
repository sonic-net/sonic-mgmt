# asic_instance

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Retrieves the asic instance given an asic id. Device must be multi-ASIC

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname, enum_frontend_asic_index):
    duthost = duthosts[rand_one_dut_hostname]

    im_facts = duthost.asic_instance(enum_frontend_asic_index)
```

## Arguments
- `asic_index` - asic index for desired instance
    - Required: `True`
    - Type: `Integer`

## Expected Output
The ASIC instance corresponding to the provided ID.S