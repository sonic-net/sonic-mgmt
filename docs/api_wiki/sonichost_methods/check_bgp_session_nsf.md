# check_bgp_session_nsf

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Checks if BGP neighbor session has entered Nonstop Forwarding(NSF) state

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    bgp_nbrs = duthost.get_bgp_neighbors()

    rand_bgp_ip = random.choice(bgp_nbrs.keys())

    is_nsf = duthost.check_bgp_session_nsf(rand_bgp_ip)
```

## Arguments
 - `neighbor_ip` - BGP IP of neighbor NSF status is desired for
    - Required: `True`
    - Type: `String`

## Expected Output
`True` if BGP session is in NSF state, `False` otherwise.