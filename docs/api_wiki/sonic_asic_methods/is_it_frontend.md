# is_it_frontend

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Checks whether ASIC is a frontend node.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname, tbinfo, enum_frontend_asic_index):
    duthost = duthosts[rand_one_dut_hostname]

    sonic_asic = duthost.asic_instance(asic_index=enum_frontend_asic_index)

    is_front = sonic_asic.is_it_frontend()
```

## Arguments
Takes no arguments.

## Expected Output
`True` if ASIC is a frontend node, `False` otherwise.