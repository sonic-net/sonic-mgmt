# start_service

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Starts service on sonichost if service is a default service. Otherwise service is started on each ASIC.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    duthost.start_service("swss")
```

## Arguments
- `service` - name of service to start
    - Required: `True`
    - Type: `String`

## Expected Output
Provides no output