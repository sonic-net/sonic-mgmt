# start_pmon_daemon

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Start daemon in pmon docker using `supervisorctl start`

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    duthost.start_pmon_daemon("pmon_daemon")
```

## Arguments
- `daemon_name` - name for daemon once started
    - Required: `True`
    - Type: `String`

## Expected output
Provides no output