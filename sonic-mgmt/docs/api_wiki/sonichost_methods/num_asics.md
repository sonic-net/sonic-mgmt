# num_asics

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Provides number of asics

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    n_npus = duthost.num_asics()
```

## Arguments
This method takes no arguemnts

## Expected Output
An integer representing the number or ASICS on the host.