# get_docker_cmd

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Provides modified command to be run on a specific docker container given an initail command and the name of the desired container.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname, tbinfo, enum_frontend_asic_index):
    duthost = duthosts[rand_one_dut_hostname]

    sonic_asic = duthost.asic_instance(asic_index=enum_frontend_asic_index)

    dkr_cmd = sonic_asic.get_docker_cmd("redis-cli --raw -n 6 keys TRANSCEIVER_INFO\*", "database")
```

## Arguments
- `cmd` - command that should be modified
    - Required: `True`
    - Type: `String`
- `container_name` - Name of the container `cmd` should be specified for
    - Required: `True`
    - Type: `String`

## Expected Output
The command as a `String` that has been modified so that it runs on the specified container