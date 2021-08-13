# critical_servies_status

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Checks status for cirtical services.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    service_statuses = duthost.critical_services_status()
```

## Arguments
Takes no arguments.

## Expected Output
Returns dictionary mapping service name to whether that service is started.

- `{SERVICE_NAME}` - `True` if service specified is started, `False` otherwise.