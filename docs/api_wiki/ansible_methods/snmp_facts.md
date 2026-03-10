# snmp_facts

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Retreives facts for device using SNMP

## Examples
```
def test_fun(localhost):
    facts = localhost.snmp_facts(host=duthost.mgmt_ip, version="v2c", community="public")
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
- `is_dell` - Whether NOS is dell or not
    - Required: `False`
    - Type: `Boolean`
- `is_eos` - Whether NOS is EOS or not
    - Required: `False`
    - Type: `Boolean`
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
Dictionary with system info gathered by SNMP. The dictionary hierarchy is described below, with each indentation describing a sub-dictionary:

- `ansible_facts`
    - `ansible_sysdescr` - system description
    - `ansible_syslocation` - community
    - `snmp_lldp` - Dictionary with LLDP info
        - `lldpLocSysDesc`
        - `lldpLocSysName`
        - `lldpLockChassisId`
        - `lldpLocChassisIdSubtype`
    - `ansible_sysuptime` - uptime for device in seconds
    - `ansible_sysname` - system name
    - `ansible_sysTotalBuffMemory` - (KB?) of buffer memory
    - `ansible_sysCachedMemory` - (KB?) of cached memory
    - `ansible_sysTotalMemory` - (KB?) of total memory
    - `ansible_sysobjectid` - system object id
    - `ansible_sysTotalSharedMemory` - (KB?) of shared memory
    - `ansible_syscontact` - Contact info for device
    - `anisble_all_ipv4_addresses`
