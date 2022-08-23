# feature_facts

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Provides the statuses for all active features on a host.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    feat_facts = duthost.feature_facts()
```

## Arguments
This method takes no Arguments

## Expected Output
Returns a dictionary with information on the features. The dictionary hierarchy is described below, with each indentation describing a sub-dictionary:

- `ansible_facts`
    - `feature_facts`
        - `{FEATURE_NAME}` - `enabled`\\`disabled`