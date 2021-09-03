# find

- [Overview](#overview)
- [Examples](#examples)
- [Expected Output](#expected-output)
- [Arguments](#arguments)

## Overview
Finds list of files based on specified criteria.

[docs](https://docs.ansible.com/ansible/latest/collections/ansible/builtin/find_module.html) used to generate this page.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    bgp_info = duthost.find(paths=["/home/admin/"], patterns=["*.py"])
```

## Arguments

- `paths` - List of directories to be searched
    - Required: `True`
    - Type: `List`
        - Element-Type: `String`
    - Aliases: `name`, `path`

- `age` - selects files whose age is greater than or equal to the specified time. Negative age indicates that selected files should be less than or equal to the specified time. Times can be specified in seconds, minutes, hours, days, or weeks using the first letter of each word (e.g. `"2w"` or `"10s"`)
    - Required: `False`
    - Type: `String`

- `age_stamp` - Choose property that `age` argument is compared to
    - Required: `False`
    - Type: `String`
    - Default: `mtime`
    - Choices:
        - `atime` - Access time. Last time file was read
        - `ctime` - Inode change time. Changes when file written to or permissions/owner is changed
        - `mtime` - Modification time. Changes when file written to

- `contains` - Regular expression or pattern matched against file content. Only work when sub-path is a file and not a directory.
    - Required: `False`
    - Type: `String`

- `depth` - Sets max number of levels to descend to. Overridden by `recurse=False`
    - Required: `False`
    - Type: `Integer`
    - Default: no limit on depth

- `excludes` - List of shell or regex patterns (see `use_regex`) that will exclude the files with matching names from the returned list
    - Required: `False`
    - Type: `List`
        - Element-Type: `string`

- `file_type` - Type of file to select
    - Required: `False`
    - Type: `String`
    - Default: `file`
    - Choices:
        - `any`
        - `directory`
        - `file`
        - `link`

- `follow` - Whether or not to follow symlinks
    - Required: `False`
    - Type: `Boolean`
    - Default: `False`

- `get_checksum` - Whether or not to generate SHA1 checksum for each file
    - Required: `False`
    - Type: `Boolean`
    - Default: `False`

- `hidden` - Whether or not to include hidden files
    - Required: `False`
    - Type: `Boolean`
    - Default: `False`

- `read_whole_file` - Whether whole file should be read into memory or whether regex should be applied line by line.
    - Required: `False`
    - Type: `Boolean`
    - Default: `False`

- `recurse` - Whether search should recursively descend into sub-directories
    - Required: `False`
    - Type: `Boolean`
    - Default: `False`

- `size` - Select files whose size is greater than or equal to the size specified. Negative size indicates desired output is less than or equal to specified size. Bytes, kilobytes, megabytes, gigabytes and terabytes can be specified using the first letter (i.e. `"1000b"`, `"3g"`). Unqualified sizes default to bytes.
    - Required: `False`
    - Type: `String`

- `use_regex` - whether patterns should use shell style patterns or regex.
    - Required: `False`
    - Type: `Boolean`
    - Default: `False`

## Expected Output
Returns dictionary that provides information on the process as well as stats on the discovered files.

- `examined` - Number of files examined
- `matched` - Number of files matched
- `files` - List of dictionaries corresponding to each matched file. For description of dictionary, see output of [duthost.stat](stat.md)