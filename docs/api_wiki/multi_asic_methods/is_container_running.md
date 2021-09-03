# is_container_running

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Returns whether or not a container is running on sonichost if the container's associated service is a default service. Otherwise, it returns whether or not the container is running on _any_ ASIC.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    is_swss_cont_run = duthost.is_container_running("swss")
```

## Arguments
- `service` - name of container to check state for
    - Required: `True`
    - Type: `String`

## Expected Output
`True` if container is running, `False` otherwise. Will check sonichost if container's associated service is a default service. Otherwise it will check if the container is running on _any_ of the ASICs.