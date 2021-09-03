# start_service

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Starts an ASIC service on its corresponding ASIC docker.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname, tbinfo, enum_frontend_asic_index):
    duthost = duthosts[rand_one_dut_hostname]

    sonic_asic = duthost.asic_instance(asic_index=enum_frontend_asic_index)

    sonic_asic.start_service("swss")
```

## Arguments
- `service` - name of service to start
    - Required: `True`
    - Type: `String`

## Expected Output
Provides no output.