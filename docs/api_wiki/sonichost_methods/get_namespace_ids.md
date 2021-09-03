# get_namespace_ids

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Gets ids of namespace where the container should reside in.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    containers_states, succeeded = duthost.get_feature_status()

    if not succeeded:
        raise Exception("Get duthost feature status failed")

    for container_name, state in containers_states.items():
        namespace_ids, succeeded = duthost.get_name_space_ids(container_name)
```

## Arguments
- `container_name` - name of container ids are desired for
    - Required: `True`
    - Type: `String`

## Expected Output
List containing the Ids of the namespaces the container should reside in