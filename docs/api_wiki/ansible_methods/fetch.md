# fetch

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Copies file from remote host to local host. 

This method may not perform as expected. Given a remote src, a local dest, and the hostname of the remote device, the final location will look like this on the local machine:

`path/to/dest/hostname/path/to/src/file.txt`

To change this refer to argument `flat`

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    duthost.fetch(src="/remote/file/path.txt/", dest="/local/file/path.txt")
```

## Arguments
- `src` - Source of file on the remote host
    - Required: `True`
    - Type: `String`
- `dest` - Destination for file on local host
    - Required: `True`
    - Type: `String`
- `fail_on_missing` - Whether task should fail if file is not found at `src`
    - Required: `False`
    - Type: `Boolean`
    - Default: `True`
- `flat` - If `False`, file will be copied to `path/to/local/dest/remote_hostname/path/to/remote/src/file`. If `True`, file will be copied to `path/to/local/dest/file`.
    - Required: `False`
    - Type: `Boolean`
    - Default: `False`
- `validate_checksum` - Verify that source and destination checksums match
    - Required: `False`
    - Type: `Boolean`
    - Default: `True`

## Expected Output
This method provides no useful output.