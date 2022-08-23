# critical_services

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

`property`

## Overview
Provides a list of critical services running on the SONiC host.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    service_lst = duthost.critical_services
```

## Arguments
Takes no arguments

## Expected Output
Provides list of strings representing the names of the critical services