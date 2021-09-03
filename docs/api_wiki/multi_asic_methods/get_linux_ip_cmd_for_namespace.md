# get_linux_ip_cmd_for_namespace

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Specifies a linux `ip` command for the provided namespace.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    namespaces = duthost.get_backend_asic_namespace_list()

    lin_ip_cmd = duthost.get_linux_ip_cmd_for_namespace("ip link show | grep -c PortChannel", namespaces[0])
```

## Arguments
- `cmd` - command to be specified for `namespace`
    - Required: `True`
    - Type: `String`
- `namespace` - namespace `cmd` should be specified for
    - Required: `True`
    - Type: `String`

## Expected Output
A modified command specified for the provided namespace.