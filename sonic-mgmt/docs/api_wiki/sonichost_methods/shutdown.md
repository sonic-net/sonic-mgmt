# shutdown

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)


## Overview
Shuts down a specified interface

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    shut = duthosts.shutdown("Ethernet0")
```

## Arguments
- `ifname` - Name of interface to be shut down
    - Required: `True`
    - Type: `String`

## Expected Output
This method does not provide much useful info.
