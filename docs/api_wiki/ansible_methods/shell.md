# shell

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Runs commands on the remote host. 

Similar to [command](command.md) except that it runs commands through a shell `/bin/sh`.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    free_form_ret = duthost.shell("ls -ltr")
    cmd_ret = duthost.shell(cmd="ls -ltr")
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
Dictionary with information on command output:

- `cmd` - the command executed by task
- `delta` - the command execution time
- `end` - The command end time
- `msg` - whether the associated task was in a `changed` state
- `rc` - return code for command
- `start` - the command execution start time
- `stderr` - The standard error as a string
- `stderr_lines`- The standard error as a list of strings
- `stdout` - the standard output as a string
- `stdout_lines` - the standard output as a list of strings