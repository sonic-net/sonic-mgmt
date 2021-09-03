# get_asic_namespace

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Provides namespace for ASIC.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname, tbinfo, enum_frontend_asic_index):
    duthost = duthosts[rand_one_dut_hostname]

    sonic_asic = duthost.asic_instance(asic_index=enum_frontend_asic_index)

    ns = sonic_asic.get_asic_namespace()
```

## Arguments
Takes no arguments.

## Expected Output
Namespace as a `String` for ASIC.