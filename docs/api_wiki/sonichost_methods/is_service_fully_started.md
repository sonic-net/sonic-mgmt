# is_service_fully_started

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Checks whether a service is fully started on the SONiC host.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    swss_started = duthost.is_service_fully_started("swss")
```

## Arguments
- `service` - Service that should be checked for `started` state
    - Required: `True`
    - Type: `String`

## Expected Output
`True` if service exists and is fully started, `False` otherwise