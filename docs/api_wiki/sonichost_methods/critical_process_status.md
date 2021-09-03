# critical_process_status

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Gets status of service and provides list of exited and running member processes.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    crit_proc_stat = duthost.critical_process_status("swss")
```

## Arguments
- `service` - name of service status is desired for
    - Required: `True`
    - Type: `String`

## Expected Output
Dictionary with info on status of service:

- `status` - `True` if service, service group and member processes for service are running, `False` otherwise
- `exited_critical_processes` - List containing names of exited member processes for specified `service`
- `running_critical_processes` - List containing names of running member processes for specified `service`