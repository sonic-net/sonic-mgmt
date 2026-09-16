# get_acl_counter

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)
- [Potential Exception](#potential-exception)

## Overview

Read ACL counter of specific ACL table and ACL rule.

## Examples

```python
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    packets_count = duthost.get_acl_counter('YOUR_ACL_TABLE', 'YOUR_ACL_RULE')
```

## Arguments

- `acl_table_name` - name of ACL table
    - Required: `True`
    - Type: `String`
- `acl_rule_name` - name of ACL rule
    - Required: `True`
    - Type: `String`
- `timeout` - maximum time (in second) to wait until ACL counter available.
    - Required: `False`
    - Type: `Integer`
    - Default: `tests.common.devices.constants.ACL_COUNTERS_UPDATE_INTERVAL_IN_SEC * 2`
- `interval` - retry interval (in second) between read ACL counter.
    - Required: `False`
    - Type: `Integer`
    - Default: `tests.common.devices.constants.ACL_COUNTERS_UPDATE_INTERVAL_IN_SEC`

## Expected Output

Returns an `Integer` indicates the count of packets hit the specific ACL rule.

Example output:

```json
1
```

## Potential Exception

- `AssertionError` - If argument `timeout < 0` or `interval <= 0`.
- `ValueError` - If `aclshow -a` returns an invalid string on DUT.
- `Exception` - If `aclshow -a` still returns `N/A` after `timeout` seconds.
