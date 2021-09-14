# stat

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Retrieves facts on specified file.

[docs](https://docs.ansible.com/ansible/latest/collections/ansible/builtin/stat_module.html) used to generate this page.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    file_stat = duthost.stat(path="/home/admin/test_file.py")
```

## Arguments

- `path` - full path to desired object/file
    - Required: `True`
    - Type: `String`
    - Aliases
        - `dest`
        - `name`

- `checksum_algorithm` - Algorithm used to generate checksum for file
    - Required: `False`
    - Type: `String`
    - Default: `sha1`
    - Options:
        - `md5`
        - `sh1`
        - `sha224`
        - `sha256`
        - `sha384`
        - `sha512`
    - Aliases:
        - `checksum`
        - `checksum_algo`

- `follow` - Whether or not to follow symlinks
    - Required: `False`
    - Type: `Boolean`
    - Default: `False`

- `get_attributes` - Gets attributes using `lsattr` tool
    - Required: `False`
    - Type: `Boolean`
    - Default: `True`
    - Aliases
        - `attr`
        - `attributes`

- `get_checksum` - Whether or not to generate a checksum for the file
    - Required: `False`
    - Type: `Boolean`
    - Default: `True`

- `get_mime` - Uses file utility to provide data on the nature of the file.
    - Required: `False`
    - Type: `Boolean`
    - Default: `True`
    - Aliases:
        - `mime`
        - `mime_type`
        - `mime-type`

## Expected Output

Returns dictionary of stats regarding the provided file (whether or not the file actually exists). Keys with an '*' next to them are defined even if the file does not exist. The dictionary hierarchy is described below, with each indentation describing a sub-dictionary:

- `stat` - The dictionary containing the stats
    - `atime` - Time of last access
    - `attributes` - List of file attributes
    - `charset` - charset used for encoding the file
    - `checksum` - generated checksum for file
    - `ctime` - Time of last metadata update/creation
    - `dev` - Device inode is on
    - `executable` - Whether user invoking stat has permissions to execute the file.
    - `exists`* - Whether or not the destination exists
    - `gid` - Numeric id representing group of the owner
    - `gr_name` - Group name of owner
    - `inode` - Inode number of path
    - `isblk` - Whether path is block device
    - `ischr` - Whether path is character device
    - `isdir` - Whether path is a directory
    - `isfifo` - Whether path is a named pipe
    - `isgid` - Whether invoking user group id matches owner group id
    - `islnk` - Whether path is a symlink
    - `isreg` - Whether path is a regular file
    - `issock` - Whether path is unix domain socket
    - `isuid` - Wheter user id matches owner id
    - `lnk_source` - Source of symlink
    - `lnk_target` - target for symlink
    - `mimetype` - file magic data
    - `mode` - Unix permissions of file in octal
    - `mtime` - time of last modification
    - `nlink` - number of links ot the inode
    - `path` - Full path to file
    - `pw_name` - User name of owner
    - `readable` - Whether invoking user can read file
    - `rgrp` - Whether owner group can read file
    - `roth` - Whether others can read file
    - `rusr` - Whether owner can read file
    - `size` - size in bytes of file
    - `uid` - numeric id representing owner
    - `wgrp` - whether owner group can write to file
    - `woth` - Whether others can write to file
    - `writable` - Whether invoking user can write to file
    - `wusr` - Whether owner can write to file
    - `xgrp` - Whether owner group can execute file
    - `xoth` - Whether others can execute file
    - `xusr` - Whether owner can execute file