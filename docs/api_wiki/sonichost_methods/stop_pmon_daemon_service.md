# stop_pmon_daemon_service

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Stops daemon in pmon docker using `supervisorctl stop`

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    duthost.stop_pmon_daemon_service("pmon_daemon")
```

## Arguments
- `daemon_name` - name of daemon to stop
    - Required: `True`
    - Type: `String`

## Expected Output
Provides no output.