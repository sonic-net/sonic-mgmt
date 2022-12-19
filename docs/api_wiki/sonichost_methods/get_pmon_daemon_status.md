# get_pmon_daemon_status

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Get daemon status in pmon docker using `supervisorctl status` command.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    pmon_status = duthost.get_pmon_daemon_status("pmon_daemon")
```

## Arguments
- `daemon_name` - name of pmon daemon
    - Required: `True`
    - Type: `String`

## Expected Output
Returns tuple with the following information:

1. The daemon status (`RUNNING`, `STOPPED`, `EXITED`)
2. The daemon pid