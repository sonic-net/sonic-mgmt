# shell_cmds

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Allows you to run mutliple commands on a remote host.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    duthost.shell_cmds(cmds=["ls /home", "pwd", "touch /home/test_file.txt", "ls /home"])
```

## Arguments
- `cmds` - List of commands to be run on the remote host
    - Required: `True`
    - Type: `List`
        Element-Type: `String`
- `continue_on_fail` - Whether the remote host should continue to run commands after a failed command
    - Reguired: `False`
    - Type: `Boolean`
    - Default: `True`

## Expected Output
A dictionary with results from commands run. The dictionary hierarchy is described below, with each indentation describing a sub-dictionary:

- `end` - Datetime for when the commands finished running
- `cmds` - the list of commands that were run
- `start` - Datetime for when the commands started running
- `delta` - difference between `start` and `end`
- `results` - List of dictionaries, each corresponding to the results for one of the commands run
    - `stderr_lines` - What was printed to stderr (split by line) during execution of command
    - `stderr` - What was printed to stderr (as one string) during execution of command
    - `stdout_lines` - What was printed to stdout (split by line) during execution of command
    - `stdout` - What was printed to stdout (as one string) during execution of command
    - `cmd` - command that was run
    - `rc` - return code