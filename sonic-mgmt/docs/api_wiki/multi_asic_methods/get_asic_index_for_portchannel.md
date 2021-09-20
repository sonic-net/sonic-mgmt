# get_asic_instance_for_portchannel

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Gets asic index associated with provided portchannel.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    asic_for_pc = duthost.get_asic_index_for_portchannel("PortChannel0001")
```

## Arguments
- `portchannel` - name of portchannel to get asic index for
    - Required: `True`
    - Type: `String`

## Expected Output
Provides associated asic_index for portchannel provided.