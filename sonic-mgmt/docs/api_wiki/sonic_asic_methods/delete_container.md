# delete_container

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Deletes a ASIC specific docker.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname, tbinfo, enum_frontend_asic_index):
    duthost = duthosts[rand_one_dut_hostname]

    sonic_asic = duthost.asic_instance(asic_index=enum_frontend_asic_index)

    sonic_asic.delete_container("swss")
```

## Arguments
- `service` - name of docker container to delete
    - Required: `True`
    - Type: `String`

## Expected Output
Provides no output.