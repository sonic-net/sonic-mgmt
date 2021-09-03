# run_redis_cmd

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Runs a redis command on the DUT.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname, enum_frontend_asic_index):
    duthost = duthosts[rand_one_dut_hostname]

    sonic_asic = duthost.asic_instance(asic_index=enum_frontend_asic_index)

    redis_out = sonic_asic.run_redis_cmd(argv=["redis-cli", "-n", "4", "hget", "DEVICE_METADATA|localhost", "buffer_model"])
```

## Arguments
- `argv` - List of strings containing command and options
    - Required: `True`
    - Type: `List`
        - Element-Type: `String`

## Expected Output
Returns a List of lines representing new-line separated stdout.