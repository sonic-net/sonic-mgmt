# get_networking_uptime

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Returns time since `networking` service started on the host.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    time_since_networking = duthost.get_networking_uptime()
```

## Arguments
Takes no arguments.

## Expected Output
Returns time since `networking` service started. Returns `None` if there was an excpetion in getting the duration.