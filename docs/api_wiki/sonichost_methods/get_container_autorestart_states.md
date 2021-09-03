# get_container_autorestart_states

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Get container names and their autorestart states. Containers that do not have the autorestart feature implemented are skipped by this test.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    container_states = duthost.get_container_autorestart_states()
```

## Arguments
This method takes no arguments

## Expected Output
Returns dictionary mapping container names to the state of the autorestart feature

- {`CONTAINER_NAME`} - Either `enabled` or `disabled` describing state of autorestart feature for provided container