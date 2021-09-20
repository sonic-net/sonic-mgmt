# get_portchannel_and_members_in_ns

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Finds a portchannel present on ASIC interface's namspace and returns its name and members.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname, enum_frontend_asic_index, tbinfo):
    duthost = duthosts[rand_one_dut_hostname]

    sonic_asic = duthost.asic_instance(asic_index=enum_frontend_asic_index)

    pc_on_asic = sonic_asic.get_portchannel_and_members_in_ns(tbinfo)
```

## Arguments
- `tbinfo` - testbed info
    - Required: `True` (though not used in method. Someone should update this.)
    - Type: `Dictionary`

## Expected Output
A tuple with the following ordered items:

1. Name of portchannel found
2. List of portchannel members

If no portchannels could be found, `None` is returned.