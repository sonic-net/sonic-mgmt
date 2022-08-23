# all_critical_process_status

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Provides summary and status of all critical services and their processes

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    crit_proc = duthost.all_critical_process_status()
```

## Arguments
This method takes no arguments.

## Expected Output
Returns a dictionary providing a summary of the statuses of all critical services and their processes. The dictionary hierarchy is described below, with each indentation describing a sub-dictionary:

- `{SERVICE_NAME}` - Dictionary describing status of processes belonging to the specified service
    - `status` - `True` if all processes belonging to service are up, otherwise `False`
    - `exited_critical_process` - List of all processes for service that have exited. Should be empty if `status` is `True`
    - `running_critical_process` - List of all processes for service that are currently running.