# delete_container

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Deletes container on sonichost if container's associated service is a default service. Otherwise, container is deleted on each ASIC.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    duthost.delete_container("swss")
```

## Arguments
- `service` - name of container to delete
    - Required: `True`
    - Type: `String`

## Expected Output
Provides no output