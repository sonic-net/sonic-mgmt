# port_on_asic

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Checks if provided port is configured on ASIC instance

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname, enum_frontend_asic_index):
    duthost = duthosts[rand_one_dut_hostname]

    sonic_asic = duthost.asic_instance(asic_index=enum_frontend_asic_index)

    eth0_on_asic = sonic_asic.port_on_asic("Ethernet0")
```

## Arguments
- `portname` - name of port to check for
    - Required: `True`
    - Type: `String`

## Expected Output
`True` if port specified is configured, `False` otherwise