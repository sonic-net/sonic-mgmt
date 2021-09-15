# is_frontend_node

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Checks whether the DUT is a frontend node. Used in multi-DUT setups.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    dut_front = duthost.is_frontend_node()
```

## Arguments
Takes no arguments.

## Expected Output
`True` if DUT is a frontend node, `False` otherwise.