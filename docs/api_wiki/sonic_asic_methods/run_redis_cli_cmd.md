# run_redis_cli_cmd

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Runs redist cmd through redis CLI for ASIC that calls method.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname, tbinfo, enum_frontend_asic_index):
    duthost = duthosts[rand_one_dut_hostname]

    sonic_asic = duthost.asic_instance(asic_index=enum_frontend_asic_index)

    ret_code = sonic_asic.run_redis_cli_cmd("client list")
```

## Arguments
- `redis_cmd` - Redis command that needs to be run
    - Required: `True`
    - Type: `String`

## Expected Output
The return code from the command.