# restart_service

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Restarts a service on the sonichost if the service is a default service. Otherwise service is restarted on each ASIC.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    duthost.restart_service("swss")
```

## Arguments
- `service` - service to be restarted
    - Required: `True`
    - Type: `String`

## Expected Output
Provides no output