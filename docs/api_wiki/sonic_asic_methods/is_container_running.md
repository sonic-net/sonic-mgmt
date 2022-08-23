# is_container_running

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Returns whether or not a specified ASIC specific container is running.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname, tbinfo, enum_frontend_asic_index):
    duthost = duthosts[rand_one_dut_hostname]

    sonic_asic = duthost.asic_instance(asic_index=enum_frontend_asic_index)

    swss_running = sonic_asic.is_container_running("swss", "swss")
```

## Arguments
- `service_name` - name of service docker corresponds to
    - Required: `True`
    - Type: `String`
- `docker_name` - name of docker container that is being checked on
    - Required: `True`
    - Type: `String`

## Expected Output
`True` if docker container is running, `False` otherwise.