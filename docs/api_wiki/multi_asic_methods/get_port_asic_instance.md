# get_port_asic_instance

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Returns the numeric ASIC instance that a provided port belongs to. Will fail test if ASIC instance is not found for provided port.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    asic = duthost.get_port_asic_instance(DESIRED_PORT)
```

## Arguments
- `port` - desired port name to get ASIC instance for
    - Required: `True`
    - Type: `String`

## Expected Output
Returns an ASIC instance corresponding to the provided port.