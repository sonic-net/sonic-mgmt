# get_pmon_daemon_db_value

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Gets the db value in state db to check the daemon expected status

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    pmon_db_val = duthost.get_pmon_daemon_db_value("PCIE_DEVICES|status", "status")
```

## Arguments
- `daemon_db_table_key` - table key for daemon db
    - Required: `True`
    - Type: `String`
- `field` - desired field
    - Required: `True`
    - Type: `String`

## Expected Output
PMON daemon db value as a String corresponding to provided info.