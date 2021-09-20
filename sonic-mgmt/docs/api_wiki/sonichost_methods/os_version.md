# os_version

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

`property`

## Overview
Provides string representing the version of SONiC being used

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    vsonic = duthost.os_version
```

## Arguments
Takes no arguments.

## Expected Output
String representing the version of SONiC being used