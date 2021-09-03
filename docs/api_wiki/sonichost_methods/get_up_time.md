# get_up_time

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Returns `datetime` object representing date/time that device was started.

Not to be confused with [get_uptime](get_uptime.md) that returns how long device has been up.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    up_time_dattime = duthost.get_up_time()
```

## Arguemnts
Takes no arguments.

## Expected Output
Returns datetime object representing the date and time that the device was first 'up'.