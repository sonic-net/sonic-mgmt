# is_container_running

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Checks whether a docker container is running.

## Example
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    is_cont_running = duthost.is_container_running({DOCKER_CONTAINER_NAME})
```

## Arguments
- `service` - Name of docker container
    - Required: `True`
    - Type: `String`

## Expected Output
`True` if container is running, `False` otherwise