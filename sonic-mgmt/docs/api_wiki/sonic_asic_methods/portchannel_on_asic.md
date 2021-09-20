# portchannel_on_asic

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
CHecks whether a specified portchannel is configured on ASIC instance

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname, enum_frontend_asic_index):
    duthost = duthosts[rand_one_dut_hostname]

    sonic_asic = duthost.asic_instance(asic_index=enum_frontend_asic_index)

    port_chnl_1 = duthost.portchannel_on_asic("PortChannel0001")
```

## Arguments
- `portchannel` - name of portchannel to check for
    - Required: `True`
    - Type: `String`

## Expected Output
`True` if portchannel is configured, `False` otherwise.