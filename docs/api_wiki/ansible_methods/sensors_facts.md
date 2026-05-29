# sensors_facts

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Retrieves sensor facts for a device.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname, creds):
    duthost = duthosts[rand_one_dut_hostname]

    platform = duthost.facts['platform']

    sensors_checks = creds['sensors_checks']

    sensors = duthost.sensors_facts(checks=sensors_checks[platform])
```

## Arguments
- `checks` - What hardware platform to check sensors for
    - Required: `True`
    - Type: `String`

## Expected Output
Unable to check output as on virtual testbed.
