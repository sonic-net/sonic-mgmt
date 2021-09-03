# stop_service

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Stops a specified service

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    duthost.stop_service("swss", {docker_name})
```

## Arguments
- `service_name` - name of service
    - Required: `True`
    - Type: `String`
- `docker_name` - name of docker containing service
    - Required: `True`
    - Type: `String`

## Expected Output
This method has no output.