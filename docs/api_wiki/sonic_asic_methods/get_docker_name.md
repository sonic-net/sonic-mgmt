# get_docker_name

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Gets ASIC specific name for docker container.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname, tbinfo, enum_frontend_asic_index):
    duthost = duthosts[rand_one_dut_hostname]

    sonic_asic = duthost.asic_instance(asic_index=enum_frontend_asic_index)

    swss_docker_name = sonic_asic.get_docker_name("swss")
```

## Arguments
- `service` - name of docker container that should be specified for the calling ASIC
    - Required: `True`
    - Type: `String`

## Expected Output
`String` reprenting the modified name.