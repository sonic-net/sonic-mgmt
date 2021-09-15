# reset_critical_services_tracking_list

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Modifies the list of critical services used by the SONiC Host.

Does not modify the services reported by [critical_services](critical_services).

This does not actually change what services are running on the host.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    duthost.reset_critical_services_tracking_list(["swss", "syncd"])
```

## Arguments
- `service_list` - The list that will be used as the `critical_services` list
    - Required: `True`
    - Type: `List`
        - Element-Type: `String`

## Expected Output
No output is provided.