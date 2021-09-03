# lldp_facts

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Retrieve LLDP facts using SNMP

## Examples
```
def test_fun(localhost, duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    facts = localhost.lldp_facts(host=duthost.mgmt_ip, version='v2c', community="public")
```

## Arguments
- `host` - IP for desired host to get lddp facts for
    - Required: `True`
    - Type: `String`
- `version` - SNMP version being used
    - Required: `True`
    - Type: `String`
    - Choices:
        - `v2`
        - `v2c`
        - `v3`
- `community` - SNMP community
    - Required: `True` if `version="v2"/"v2c"`, `False` otherwise
    - Type: `String`
- `level` - Authentication level, required for v3
    - Required: `True` if `version="v3"`, `False` otherwise
    - Type: `String`
    - Choices:
        - `authPriv`
        - `authNoPriv`
- `username` - Username for v3. Required for v3
    - Required: `True` if `version="v3"`, `False` otherwise
    - Type: `String`
- `integrity` - Hashing algorithm desired. Required for v3
    - Required: `True` if `version="v3"`, `False` otherwise
    - Type: `String`
    - Choices:
        - `md5`
        - `sha`
- `authkey` - authentication key for v3. Required for v3
    - Required: `True` if `version="v3"`, `False` otherwise
    - Type: `String`
- `privacy` - Encryption algorithm, required if `level` is `authPriv`
    - Required: `True` if `level="authPriv"`, `False` otherwise
    - Type: `String`
    - Choices:
        - `des`
        - `aes`
- `privkey` - Encryption key, required if `level` is `authPriv`
    - Required: `True` if `level="authPriv"`, `False` otherwise
    - Type: `String`

## Expected Output

# TODO
Unable to test output. Timeout on my system due to it being slow.