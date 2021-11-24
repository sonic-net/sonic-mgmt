# is_supervisor_node

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Checks if current node is a supervisor node. Used for multi-DUT setups.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    dut_sup = duthost.is_supervisor_node()
```

## Arguments
Takes no arguments.

## Expected Output
`True` if DUT is supervisor node, `False` otherwise