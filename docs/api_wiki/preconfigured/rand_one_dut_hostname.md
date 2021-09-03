# rand_one_dut_hostname

- [Overview](#overview)
- [Examples](#example)
- [Expected Output](#expected-output)

## Overview
A random hostname belonging to one of the DUT instances defined by the deployed testbed.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
```

## Expected Output
A random hostname. This hostname corresponds to one of the DUTs deployed by the current testbed.