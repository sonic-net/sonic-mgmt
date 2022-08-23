# announce_routes

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Announces Routes to the exabgp processes running in the PTF container

This method must be run from the localhost.

## Examples
```
def test_fun(localhost):
    localhost.announce_routes(topo_name="t1-lag", ptf_ip: "192.168.1.10")
```

## Arguments
- `topo_name` - Name of topology in use
    - Required: `True`
    - Type: `String`
- `ptf_ip` - IP for ptf container
    - Required: `True`
    - Type: `String`

## Expected Output
Provides no meaningful output