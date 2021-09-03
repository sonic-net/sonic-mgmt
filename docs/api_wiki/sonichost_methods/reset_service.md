# reset_service

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Resets a service on a specified docker.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    duthost.reset_service("swss", "swss")
```

## Arguments
- `service_name` - name of service to be reset
    - Required: `True`
    - Type: `String`
- `docker_name` - name of docker service is on
    - Required: `True`
    - Type: `String`

## Expected Output
Provides no output.