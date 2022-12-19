# get_swss_docker_names

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Gets list of swss docker names.

There should be a docker name for each NPU present on the DUT.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    swss_names = duthost.get_swss_docker_names()
```

## Arguments
Takes no arguments.

## Expected Output
Returns list of swss docker names. If there is only one NPU, the output should look like `["swss"]`.