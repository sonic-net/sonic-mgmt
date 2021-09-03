# get_service_name

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Provides ASIC specific service name.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname, tbinfo, enum_frontend_asic_index):
    duthost = duthosts[rand_one_dut_hostname]

    sonic_asic = duthost.asic_instance(asic_index=enum_frontend_asic_index)

    asic_swss_name = sonic_asic.get_service_name("swss")
```

## Arguments
- `service` - service that ASIC specific service name is desired for
    - Required: `True`
    - Type: `String`

## Expected Output
`String` representing the name of the service.