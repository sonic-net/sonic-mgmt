# is_backend_portchannel

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Returns whether or not a provided portchannel is a backend portchannel.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    is_backend = duthost.is_backend_portchannel("PortChannel0001")
```

## Arguments
- `port_channel` - name of portchannel to check
    - Required: `True`
    - Type: `String`

## Expected Output
`True` if `port_channel` is a backend portchannel, `False` otherwise.