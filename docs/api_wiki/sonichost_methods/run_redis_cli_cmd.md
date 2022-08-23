# run_redis_cli_cmd

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Run redis command through the redis cli.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    ret_code = duthost.run_redis_cli_cmd({REDIS_COMMAND})
```

## Arguments
- `redis_cmd` - redis command that should be run on the DUT
    - Required: `True`
    - Type: `String`

## Expected Output
The return code for the command.