# get_up_ip_ports

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Gets list of all `up` interfaces

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    up_ports = duthost.get_up_ip_ports()
```

## Arguments
Takes no arguments

## Expected Output
List of port names corresponding to the ports that are up.