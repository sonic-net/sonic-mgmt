# is_it_backend

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Checks whether the ASIC is a backend node

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname, tbinfo, enum_frontend_asic_index):
    duthost = duthosts[rand_one_dut_hostname]

    sonic_asic = duthost.asic_instance(asic_index=enum_frontend_asic_index)

    is_backend = sonic_asic.is_it_backend()
```

## Arguments
Takes no arguments.

## Expected Output
`True` if ASIC is a backend node, `False` otherwise