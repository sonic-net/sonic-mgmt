# get_queue_oid

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Get the queue OID of given port and queue number.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    duthost.get_queue_oid("Ethernet0", 4)
```

## Arguments
- `port` - port to check queue OID for
    - Required: `True`
    - Type: `String`
- `queue_num` - queue number for port provided
    - Required: `True`
    - Type: `Integer`

## Expected Output
The queue OID corresponding to given `port` and `queue_num`