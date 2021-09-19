# mgmt_ip

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

`property`

## Overview
Provides management ip for host.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    m_ip = duthost.mgmt_ip
```

## Arguments
Takes no arguments.

## Expected Output
A string representing the management ip for the host.