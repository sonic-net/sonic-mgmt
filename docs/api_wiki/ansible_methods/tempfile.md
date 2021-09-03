# tempfile

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Generates temp file or directory on remote host.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    parsed_com = duthost.tempfile(path="/home/admin/tmp", prefix="ans_")
```

## Arguments
- `path` - path for desired temp file or directory. If not specified, uses system default (probably `/tmp/`)
    - Required: `False`
    - Type: `String`
- `prefix` - Prefix to file/directory name created
    - Required: `False`
    - Type: `String`
    - Default: `ansible.`
- `state` - Whether a file or directory should be created
    - Required: `False`
    - Type: `String`
    - Default: `file`
    - Choices:
        - `file`
        - `directory`
- `suffix` - Suffix to file/directory name created
    - Required: `False`
    - Type: `String`
    - Default: `""`

## Expected Output
Dictionary that just has the path to the temp file on the remote host.

- `path` - path to created temp file or directory