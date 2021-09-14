# replace

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Replaces all instances of a pattern within a specified file. When using this method make sure that the pattern being used to match does not match the replacement text, otherwise the results may be undesirable.

[docs](https://docs.ansible.com/ansible/latest/collections/ansible/builtin/replace_module.html) used to help generate this page. 

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    repl_res = duthost.replace(path="/home/admin/test.txt", reqexp="admin", replace="user")
```

## Arguments
- `path` - path to file to be modified
    - Required: `True`
    - Type: `String`
    - Aliases:
        - `dest`
        - `destfile`
        - `name`
- `regexp` - regular expression that will used to match. Uses MULTILINE mode, which means `^` and `$` match beggining and end of file. `.` does not match newlines.
    - Required: `True`
    - Type: `String`
- `after` - regular expression that will be matched to the file content. Only content after this match will be modified.
    - Required: `False`
    - Type: `String`
- `attributes` - Attributes resulting file or directory should have (look at man page for chattr for supported flags)
    - Required: `False`
    - Type: `String`
    - Aliases:
        - `attr`
- `backup` - Create backup file including timestamp to roll back if needed
    - Required: `False`
    - Type: `Boolean`
    - Default: `False`
- `before` - Regular expression that will be matched to the file content. Only content before this match will be modified.
    - Required: `False`
    - Type: `String`
- `encoding` - Character encoding for selected file
    - Required: `False`
    - Type: `String`
    - Default: `utf-8`
- `group` - Name of group that should one the file
    - Required: `False`
    - Type: `String`
- `mode` - permissions for resulting file. Can be written symolically: "u=rw, g=r, o=rx"
    - Required: `False`
    - Type: `String`
- `owner` - Name of owner that will own the file
    - Required: `False`
    - Type: `String`
- `replace` - String that will replace the regex matches. If none is provided, all matches are removed.
    - Required: `False`
    - Type: `String`
- `selevel` - the level part of the Security Enchanced Linux file context
    - Required: `False`
    - Type: `String`
- `setype` - the type part of the Security Enchanced Linux file context
    - Required: `False`
    - Type: `String`
- `seuser` - the user part of the Security Enchanced Linux file context
    - Required: `False`
    - Type: `String`
- `unsafe_writes` - Allow unsafe writes when atomic operations fail (will still do safe writes if they do not)
    - Required: `False`
    - Type: `Boolean`
    - Default: `False`
- `validate` - validation command to be run on file
    - Required: `False`
    - Type: `Boolean`

## Expected Output
Method provides no useful output.