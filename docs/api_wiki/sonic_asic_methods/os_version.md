# os_version

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

`property`

## Overview
Provides the SONiC OS version for the sonichost associated with the calling ASIC

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname, tbinfo, enum_frontend_asic_index):
    duthost = duthosts[rand_one_dut_hostname]

    sonic_asic = duthost.asic_instance(asic_index=enum_frontend_asic_index)

    sonic_version = sonic_asic.os_version
```

## Arguments
Takes no arguments.

## Expected Output
A string representing the version of SONiC OS running on the sonichost associated with the ASIC that called the method.