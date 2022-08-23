# command

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Runs commands specified for the ASIC calling the method.

Prepends `ip netns` along with the ASIC namespace to specify the command for the ASIC.

## Exmaples
```
def test_fun(duthosts, rand_one_dut_hostname, enum_frontend_asic_index):
    duthost = duthosts[rand_one_dut_hostname]

    sonic_asic = duthost.asic_instance(asic_index=enum_frontend_asic_index)

    sonic_asic.command("ls -ltr")
```

## Arguments
- `cmdstr` - command to be run
    - Required: `True`
    - Type: `String`

## Expected Output
See the [command](../ansible_methods/command.md#expected-output) Ansible Module for expected output.