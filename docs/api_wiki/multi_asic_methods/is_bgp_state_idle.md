# is_bgp_state_idle

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Checks if all BGP peers are in IDLE state on the sonichost.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    all_bgp_idle = duthost.is_bgp_state_idle()
```

## Arguments
Takes no arguments.

## Expected Output
`True` if all BGP peers are in IDLE state, `False` otherwise.