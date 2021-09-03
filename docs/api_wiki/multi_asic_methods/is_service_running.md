# is_service_running

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Checks if a specified service is running. Can be a service within a docker.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    duthost.is_service_running("syncd")
```

## Arguments
- `service_name` - name of service
    - Required: `True`
    - Type: `String`
- `docker_name` - name of docker `service` is a member of
    - Required: `False`
    - Type: `String`
    - Default: `None` 

## Expected Output
`True` if service is running, `False` otherwise.