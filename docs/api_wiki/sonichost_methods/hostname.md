# hostname

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

`property`

## Overview
Provides hostname for device.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    hostname = duthost.hostname
```

## Arguments
This method takes no arguments.

## Expected Output
A string representing the device hostname