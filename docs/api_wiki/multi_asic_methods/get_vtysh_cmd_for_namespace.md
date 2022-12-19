# get_vtysh_cmd_for_namespace

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Provides modified VTYSH command provided ASIC namespace and command.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    new_cmd = duthost.get_vtysh_cmd_for_namespace("vtysh -c 'configure terminal'", None)
```

## Arguments
- `cmd` - Command that should be modified
    - Required: `True`
    - Type: `String`
- `namespace` - ASIC namespace command should be modified for. If `None` is specified, default namespace will be used
    - Required: `True`
    - Type: `String`


## Expected Output
Modified command will be returned as a `String`