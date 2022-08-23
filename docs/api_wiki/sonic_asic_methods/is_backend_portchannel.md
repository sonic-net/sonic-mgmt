# is_backend_portchannel

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Checks whether specified portchannel is a backend portchannel.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname, tbinfo, enum_frontend_asic_index):
    duthost = duthosts[rand_one_dut_hostname]

    sonic_asic = duthost.asic_instance(asic_index=enum_frontend_asic_index)

    is_backend = sonic_asic.is_backend_portchannel("PortChannel0001")
```

## Arguments
- `port_channel` - name of portchannel to be checked
    - Required: `True`
    - Type: `String`

## Expected Output
`True` if specified portchannel is a backend portchannel