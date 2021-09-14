# config_facts

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Retreives configuration facts for a device

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    config_facts = duthosts.config_facts(host=duthost.hostname, source="running")
```

## Arguments
- `host` - The device hostname that config facts are desired for
    - Required: `True`
    - Type: `String`
- `source` - Whether current config or boot config is desired
    - Required: `True`
    - Type: `String`
    - Choices:
        - `running` - currently running config
        - `persistent` - boot config as described in `/etc/sonic/config_db.json`
- `filename` - specific config file location (if not `/etc/sonic/config_db.json`)
    - Required: `False`
    - Type: `String`
- `namespace` - Specify ASIC namespace is desired
    - Required: `False`
    - Type: `String`

## Expected Output

Output is too long to reasonably document on this page. Though documentation should be added on commonly used features.