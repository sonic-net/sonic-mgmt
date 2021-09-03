# get_running_config_facts

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Provides information on the currently running configuration of the dut.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    config_facts = duthost.get_running_config_facts()
```

## Arguments
This method takes no arguments.

## Expected Output

Output is too long to reasonably document on this page. Though documentation should be added on commonly used features.