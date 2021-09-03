# get_uptime

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Returns the amount of time since device was started

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    time_since_start = duthost.get_uptime()
```


## Arguments
Takes no arguments.

## Expected Output
returns amount of time since device start.