# kill_pmon_daemon_pid_w_sig

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Stops daemon in pmon docker using kill with a sig.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    duthost.start_pmon_daemon("pmon_daemon")
    pid = get_phom_daemon_status("pmon_daemon")[1]

    duthost.kill_pmon_daemon_pid_w_sig(pid, "SIGINT")
```

## Arguments
- `pid` - pid for daemon in pmon docker
    - Required: `True`
    - Type: `Integer`
- `sig_name` - name of desired signal for kill
    - Requierd: `True`
    - Type: `String`

## Expected Output
Provides no output.