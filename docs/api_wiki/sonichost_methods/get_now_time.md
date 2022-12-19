# get_now_time

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Gets current datetime as defined on the remote host

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    duthosttime = duthost.get_now_time()
```

## Arguments
This method takes no arguments.

## Expected Output
A string representing the datetime (`Y-M-D H:M:S`)