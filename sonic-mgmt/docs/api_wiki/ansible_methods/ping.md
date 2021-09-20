# ping

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Pings the remote host

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    ping = duthost.ping(data="I hear you")
```

## Arguments
- `data` - Data to be returned
    - Required: `False`
    - Type: `String`
    - Default: `pong`

## Expected Output
Dictionary with value returned from host.

- `ping` - Value returned from host