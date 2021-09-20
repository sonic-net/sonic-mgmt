# has_config_subcommand

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Check if a config or show subcommand exists on the remote host. *WARNING*: to test whether it exists, the method will run the command. Ensure that there will be no negative sid-effects of having this command run on the remote host.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    has_vlan_proxy_arp = duthost.has_config_subcommand('config vlan proxy_arp')
```

## Arguments
- `command` - Command to be tested
    - Required: `True`
    - Type: `String`

## Expected Output
`True` if command exists, a `False` otherwise.