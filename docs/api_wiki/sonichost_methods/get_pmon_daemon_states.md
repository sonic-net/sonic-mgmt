# get_pmon_daemon_states

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Get states of daemons from the pmon docker.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    daemon_states = duthost.get_pmon_daemon_states()
```

## Arguments
Takes no arguments.

## Expected Output
Dictionary with states of daemons in the pmon docker:

- `{DAEMON_NAME}` - state of daemon specified