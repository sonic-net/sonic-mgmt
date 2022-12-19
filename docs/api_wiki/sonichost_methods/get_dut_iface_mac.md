# get_dut_iface_mac

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Gets the AMC address for specified interface

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    interface_stats = duthost.show_interface(command="status")
    rand_interface_name = random.choice(interface_stats["ansible_facts"]["int_status"].keys())

    duthost.get_dut_iface_mac(rand_interface_name)
```
## Arguments
 - `iface_name` - name of the interface MAC address is desired for
    - Required: `True`
    - Type: `String`

## Expected Output
Mac address for specified interface. Will fail if the interface could not be found.