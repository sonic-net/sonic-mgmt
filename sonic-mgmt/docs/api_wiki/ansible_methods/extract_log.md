# extract_log

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Unrotate logs and extract information starting from a row with predefined string.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    im_facts = duthost.image_facts(directory="/tmp/logs/", file_prefix="log_", start_string="start log", target_filename="/tmp/final_logs/final_log.log")
```

## Arguments
- `directory` - Name of directory with target log files
    - Required: `True`
    - Type: `String`
    - Default: `None`
- `file_prefix` - Prefix that target log file names should start with
    - Required: `True`
    - Type: `String`
    - Default: `None`
- `start_string` - After log files are combined all lines after `start_string` are copied to `target_filename`
    - Required: `True`
    - Type: `String`
    - Default: `None`
- `target_filename` - Filename for output log
    - Required: `True`
    - Type: `String`
    - Default: `None`

## Expected Output
Provides no output