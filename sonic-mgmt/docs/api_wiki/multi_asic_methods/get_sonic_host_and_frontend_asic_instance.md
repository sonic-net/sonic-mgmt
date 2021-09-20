# get_sonic_host_and_frontend_asic_instance

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Returns sonic host and all frontend asic instances. Only works on multi-asic devices

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    im_facts = duthost.get_sonic_host_and_frontend_asic_instance()
```

## Arguments
This method takes no arguments.

## Expected Output
Returns list where first object is the sonic host. All other objects in the list are the fontend ASIC instances.