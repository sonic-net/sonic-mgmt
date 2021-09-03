# start_service

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Starts service on a specified docker.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    duthost.start_service("swss", "swss")
```

## Arguments
- `service_name` - name of service to start
    - Required: `True`
    - Type: `String`
- `docker_name` - name of docker container to start service on
    - Required: `True`
    - Type: `String`

## Expected Output
Provides no output