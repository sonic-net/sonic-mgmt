# get_rsyslog_ipv4

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Returns the rsyslog ipv4 address.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    rsyslog_ip = duthost.get_rsyslog_ipv4()
```

## Arguments
Takes no arguments.

## Expected Output
Returns `String` containing rsyslog ipv4 address.