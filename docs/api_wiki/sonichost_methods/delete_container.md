# delete_container

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Removes a docker container from the DUT.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    duthost.delete_container("swss")
```

## Arguments
- `service` - name of docker container to delete
    - Required: `True`
    - Type: `String`

## Expected Output
Provides no output.