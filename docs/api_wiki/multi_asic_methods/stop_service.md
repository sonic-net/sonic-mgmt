# stop_service

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Stops a service on the sonichost if service is a default service. Otherwise serviec is stopped on all ASICs.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    duthost.stop_service("swss")
```

## Arguments
- `service_name` - name of service
    - Required: `True`
    - Type: `String`

## Expected Output
This method has no output.