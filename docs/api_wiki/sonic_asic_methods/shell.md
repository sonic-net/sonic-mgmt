# shell

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Runs a shell command via the sonichost associated with the ASIC instance calling the method.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname, enum_frontend_asic_index):
    duthost = duthosts[rand_one_dut_hostname]

    sonic_asic = duthost.asic_instance(asic_index=enum_frontend_asic_index)

    bgp_info = sonic_asic.shell("ls -ltr")
```

## Arguments
- `chdir` - change into specified directory before running command
    - Required: `False`
    - Type: `String`
- `cmd` - The command to be run as a string with space dilineated options.
    - Required: `True` if free-form argument is not provided, `False` otherwise
    - Type: `String`
- `creates` - filename. If a matching file already exists, command _will not_ be run.
    - Required: `False`
    - Type: `String`
- `removes` - filename. If matching file exists, command _will_ be run
    - Required: `False`
    - Type: `String`
- `stdin` - Set the stdin command directly to the specified value
    - Required: `False`
    - Type: `String`
- `stdin_add_newline` - if `True`, newline is appended to stdin data
    - Required: `False`
    - Type: `Boolean`
    - Default: `True`
- `warn` - Enable or disable task warnings (deprecated)
    - Required: `False`
    - Type: `Boolean`
    - Default: `False`

## Expected Output
See the [shell](../ansible_methods/shell.md#expected-output) Ansible module for example output.