# exabgp

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Start or stop exabgp instance with certain configurations

## Examples
```
def test_fun(ptfhost):
    ptfhost.exabgp(name="t1", 
                   state="started", 
                   router_id="10.0.0.0",
                   local_ip="10.0.0.0",
                   peer_ip="10.0.0.1",
                   local_asn=65534
                   peer_asn=65535
                   port=5000
                   )
```

## Arguments
- `name` - name for exabgp instance
    - Required: `True`
    - Type: `String`
- `state` - desired state for the exabgp instance
    - Required: `True`
    - Type: `String`
    - Choices:
        - `started`
        - `restarted`
        - `stopped`
        - `present`
        - `absent`
        - `status`
- `router_id`
    - Required: `False`
    - Type: `String`
- `local_ip`
    - Required: `False`
    - Type: `String`
- `peer_ip`
    - Required: `False`
    - Type: `String`
- `local_asn`
    - Required: `False`
    - Type: `Integer`
- `peer_asn`
    - Required: `False`
    - Type: `Integer`
- `port`
    - Required: `False`
    - Type: `Integer`
    - Default: `5000`
- `dump_script`
    - Required: `False`
    - Type: `String`
    - Default: `None`
- `passive`
    - Required: `False`
    - Type: `Boolean`
    - Default: `False`

## Expected Output
No useful output is returned.