# get_syncd_docker_names

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Gets list of syncd docker names. 

There should be a docker name for each NPU present on the DUT.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    syncd_names = duthost.get_syncd_docker_names()
```

## Arguments
Takes no arguments.

## Expected Output
List of docker names. If there is only one NPU, the output should be `["syncd"]`