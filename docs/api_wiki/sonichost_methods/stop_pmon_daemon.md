# stop_pmon_daemon

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Stop daemon in pmon docker.

If only `daemon_name` is provided, daemon will be stopped as in [stop_pmon_daemon_service](stop_pmon_daemon_service.md). If `pid` and `sig_name` are also provided, daemon will be stopped as in [kill_pmon_daemon_pid_w_sig](kill_pmon_daemon_pid_w_sig.md).

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    duthost.stop_daemon("pmon_daemon")
```

## Arguments
- `daemon_name` - name of daemon
    - Required: `True`
    - Type: `String`
- `sig_name` - name of singal no be used when killing daemon
    - Required: `True` if `pid` is specified, `False` otherwise
    - Type: `String`
- `pid` - pid of daemon
    - Required: `True` if `sig_name` is specified, `False` otherwise
    - Type: `Integer`

## Expected Output
Provides no output