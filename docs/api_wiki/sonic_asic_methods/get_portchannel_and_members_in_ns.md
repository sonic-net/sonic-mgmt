# get_portchannels_and_members_in_ns

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Finds a portchannels present on ASIC interface's namspace and returns their names and members.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname, enum_frontend_asic_index, tbinfo):
    duthost = duthosts[rand_one_dut_hostname]

    sonic_asic = duthost.asic_instance(asic_index=enum_frontend_asic_index)

    pc_on_asic_dict = sonic_asic.get_portchannels_and_members_in_ns(tbinfo)
```

## Arguments
- `tbinfo` - testbed info
    - Required: `True` (though not used in method. Someone should update this.)
    - Type: `Dictionary`

## Expected Output
A dict with the following items:

1. Name of portchannel found as key
2. List of portchannel members as value

If no portchannels could be found, `{}` is returned.