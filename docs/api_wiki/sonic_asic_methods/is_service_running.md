# is_service_running

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Checks if a specified service is running. Can be a service within a docker.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname, enum_frontend_asic_index):
    duthost = duthosts[rand_one_dut_hostname]

    sonic_asic = duthost.asic_instance(asic_index=enum_frontend_asic_index)

    duthost.is_service_running("syncd", {docker_name})
```

## Arguments
- `service_name` - name of service
    - Required: `True`
    - Type: `String`
- `docker_name` - name of docker `service` is a member of
    - Required: `True`
    - Type: `String`

## Expected Output
`True` if service is running, `False` otherwise.