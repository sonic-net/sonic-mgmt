# get_monit_services_status

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Get metadata on services monitored by Monit.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    service_statuses = duthost.get_monit_services_status()
```

## Arguments
Takes no arguments.

## Expected Output
Dictionary with metadata on relevant services. The dictionary hierarchy is described below, with each indentation describing a sub-dictionary:

- `{SERVICE_NAME}` - Dictionary with metadata on specified service
    - `service_status` - current status of service
    - `service_type` - type of service