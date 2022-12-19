# service

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Controls services on the dut.

[docs](https://docs.ansible.com/ansible/latest/collections/ansible/builtin/service_module.html) that helped write this page

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    duthost.service(name="ntp", state="stopped")
```

## Arguments
- `name` - name of the service
    - Required: `True`
    - Type: `String`
- `arguments` - additional arguments provided to cli.
    - Required: `False`
    - Type: `String`
    - Aliases:
        - `args`
- `enabled` - Whether service should start on system boot
    - Required: `True` if `state` is not defined, `False` otherwise
    - Type: `Boolean`
- `pattern` - substring that will be matched against the output of the `ps` command in the even that the service does not respond to the `status` command. If the substring is found, the service is considered up.
    - Required: `False`
    - Type: `String`
- `sleep` - In the event that `state=restarted`, the number of seconds provided will pass between the stop and start command for the service
    - Required: `False`
    - Type: `Integer`
- `state` - Desired state for the service
    - Required: `True` if `enabled` is not defined, `False` otherwise
    - Type: `String`
    - Choices:
        - `reloaded` - reloads config for service
        - `restarted` - turns service off completely and back on
        - `started` - turns service on if not alraedy on
        - `stopped` - turns service off if not already off
- `use` - modules used to manage service
    - Required: `False`
    - Type: `String`
    - Default: `auto`

## Expected Output
Provides no useful output. Will error if bad args are provided.