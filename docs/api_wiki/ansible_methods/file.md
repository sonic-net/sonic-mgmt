# file

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Allows for setting attributes of file, symlinks, directories. Can be used to remove files.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    delete_file = duthost.image_facts(path="/file/to/delete.txt", state='absent')
```

## Arguments
- `path` - path to file that should be modified
    - Required: `True`
    - Type: `String`
- `access_time` - what the files access time should be set to. If `now` is provided, current time is used
    - Required: `False`
    - Type: `String`
    - Format: `YYYYMMDDHHMM.SS` (default)
- `access_time_format` - Format for `access_time`
    - Required: `False`
    - Type: `String`
    - Default: `%Y%m%d%H%M.%S`
- `follow` - Whether symlinks should be followed
    - Required: `False`
    - Type: `Boolean`
    - Default: `True`
- `force` - Force creation of symlinks if source file does not exist or if the destination exists and is a file
    - Required: `False`
    - Type: `Boolean`
    - Default: `False`
- `group` - name of group that should on the file
    - Required: `False`
    - Type: `String`
- `mode` - permissions of resulting file
    - Required: `False`
    - Type: `String`
    - Format: `u=rw,g=r,o=r`
- `modification_time` - What the files mtime should be set to
    - Required: `False`
    - Type: `String`
    - Format: `YYYYMMDDHHMM.SS` (default)
- `modification_time_format` - Format for `modification_time`
    - Required: `False`
    - Type: `String`
    - Default: `%Y%m%d%H%M.%S`
- `owner` - Name of owner that hsould own the file
    - Required: `False`
    - Type: `String`
- `recurse` - Set attributes recursively on directory contents
    - Required: `False`
    - Type: `Boolean`
    - Default: `False`
- `selevel` - the level part of the Security Enchanced Linux file context
    - Required: `False`
    - Type: `String`
- `serole` - The role part of the Security Enchanced Linux file context
    - Required: `False`
    - Type: `String`
- `setype` - the type part of the Security Enchanced Linux file context
    - Required: `False`
    - Type: `String`
- `seuser` - the user part of the Security Enchanced Linux file context
    - Required: `False`
    - Type: `String`
- `src` - Path of file to link to (for links)
    - Required: `False`
    - Type: `String`
- `state` - What should be done to the file
    - Required: `False`
    - Type: `String`
    - Default: `file`
    - Choices:
        - `absent` - file will be recursively deleted
        - `directory` - directory will be created
        - `file` - returns current state of file with modifications from other attributres. Will not create file if it does not exist.
        - `hard` - hard link will be created or changed
        - `link` - symlink will be created or changed
        - `touch` - an empty file will be created at the path specified
- `unsafe_writes` - Whether ansible should be allowed to use unsafe write in the event that atomic operations do not work
    - Required: `False`
    - Type: `Boolean`
    - Default: `False`

## Expected Output
Dictionary with basic information.

- `dest` - destination of path
- `path` - destination of path