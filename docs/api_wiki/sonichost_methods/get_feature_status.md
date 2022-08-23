# get_feature_status

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Returns features and their states.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    features_states, succeeded = duthost.get_feature_status()
```

## Arguments
This function takes no arguments

## Expected Output
Returns a tuple:
1. A dictionary mapping feature name to their state of the form: `{FEATURE_NAME}` - `enabled` or `disabled`
2. `True` if method succeeded, `False` otherwise