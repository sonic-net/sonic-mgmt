# stop_service

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Stops a specified ASIC service on the corresponding docker

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname, tbinfo, enum_frontend_asic_index):
    duthost = duthosts[rand_one_dut_hostname]

    sonic_asic = duthost.asic_instance(asic_index=enum_frontend_asic_index)

    bgp_info = sonic_asic.stop_service("swss")
```

## Arguments
- `service_name` - name of service
    - Required: `True`
    - Type: `String`

## Expected Output
This method has no output.