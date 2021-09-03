# get_critical_group_and_process_lists

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Provides lists of cirtical groups and processes

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    containers_states, succeeded = duthost.get_feature_status()

    if not succeeded:
        pytest.fail("Could not get container states")
    
    rand_container_name = random.choice(containers_states.keys())

    critical_group_proc = duthost.get_critical_group_and_process_lists(rand_container_name)
```


## Arguments
- `container_name` - name of container that groups and processes are desired for
    - Required: `True`
    - Type: `String`

## Expected Output
A three tuple containing:
1. List of running critical groups
2. List of running critical processes
3. `True` if method succeeded, otherwise `False`