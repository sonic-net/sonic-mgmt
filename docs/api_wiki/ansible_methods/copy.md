# copy

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Used to copy local files to remote host.

[docs](https://docs.ansible.com/ansible/latest/collections/ansible/builtin/copy_module.html) used to help create this page.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    duthost.copy(src="/local/file/path.txt/", dest="/remote/file/path.txt")
```

## Arguments
- `src` - desired path for file to be copied
    - Required: `True`
    - Type: `String`
- `dest` - desired destination on the remote host
    - Required: `True`
    - Type: `String`
- `attributes` - Attributes the resulting file should have
    - Required: `False`
    - Type: `String`
- `backup` - Create backup file with timestamp
    - Required: `False`
    - Type: `Boolean`
    - Default: `False`
- `checksum` - SHA1 checksum of the file being transferred. Used to validate final file. If not provided, ansible will generate it.
    - Required: `False`
    - Type: `String`
- `decrypt` - Controls autodecryption of source files using vault.
    - Required: `False`
    - Type: `Boolean`
    - Default: `True`
- `directory_mode` - For defining permissions of copied directories. Uses system defaults if not defined. Can use symbolic "u=rw,g=r,o=rx"
    - Required: `False`
    - Type: `String`
- `owner` - Name of use that should own file/directory
    - Required: `False`
    - Type: `String`
- `remote_src` - Whether `src` is on the remote host or on the calling device. 
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
- `unsafe_writes` - Allows Ansible to do unsafe_writes in the case that atomic operations are failing.
    - Required: `False`
    - Type: `Boolean`
    - Default: `False`
- `validate` - Path to validation function used to very file integrity
    - Required: `False`
    - Type: `String`


## Expected Output
Returns dictionary that provides info on the copied file.

- `backup_file` - path and name for backup file created
- `checksum` - SHA1 checksum for copied file
- `dest` - Destination path for file
- `gid` - Group id of the file
- `group` - group name of the file
- `md5sum` - MD5 checksum of the copied file
- `mode` - permissions of the copied file
- `owner` - name of owner
- `size` - size of copied file
- `src` - source file was copied from
- `state` - staet of the copied file (`file`, `directory`)
- `uid` - Owner id for the file