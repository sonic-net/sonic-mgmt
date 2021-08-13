# kernel_version

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

`property`

## Overview
Provides version of Sonic kernel on remote host

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    dut_kernel_version = duthost.kernel_version
```

## Arguments
This method takes no arguments.

## Expected Output
The Sonic kernel version of the remote host.