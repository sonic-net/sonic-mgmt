# critical_services_fully_started

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Whether all critical services have started on the SONiC host.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    all_serv_start = duthost.critical_services_fully_started()
```

## Arguments
Takes no arguments.

## Expected Output
`True` if all critical services are fully started, `False` otherwise.