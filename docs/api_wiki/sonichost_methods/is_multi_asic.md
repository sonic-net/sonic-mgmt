# is_multi_asic

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Returns whether remote host is multi-ASIC

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    is_duthost_multi_asic = duthost.is_multi_asic
```

## Arguments
This method takes no arguments.

## Expected Output
`True` if remote host is multi-ASIC, `False` otherwise.