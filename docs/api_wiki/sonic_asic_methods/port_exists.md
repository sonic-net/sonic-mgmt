# port_exists

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Checks whether a provided port exists in the ASIC instance calling the method.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname, enum_frontend_asic_index):
    duthost = duthosts[rand_one_dut_hostname]

    sonic_asic = duthost.asic_instance(asic_index=enum_frontend_asic_index)

    eth0_port = sonic_asic.port_exists("Ethernet0")
```

## Arguments
- `port` - port name to check for
    - Required: `True`
    - Type: `String`

## Expected Output
`True` if provided port exists in the ASIC instance, `False` otherwise.