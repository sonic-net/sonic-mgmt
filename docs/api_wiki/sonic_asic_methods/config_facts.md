# config_facts

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Current config facts for ASIC.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname, tbinfo, enum_frontend_asic_index):
    duthost = duthosts[rand_one_dut_hostname]

    sonic_asic = duthost.asic_instance(asic_index=enum_frontend_asic_index)

    cfg_info = sonic_asic.config_facts(host=duthost.hostname, source="running")
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
See the [config_facts](../ansible_methods/config_facts.md) ansible module for expected output.