# show_interface

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Retrieves status and counter values from DUT.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    interf_status = duthost.show_interface(command="status")
    interf_counters = duthost.show_interface(command="counter")
```

## Arguments
- `command` - Whether interface statuses or counters are desired
    - Required: `True`
    - Type: `String`
    - Choices:
        - `status`
        - `counter`
- `interfaces` - List of interface for facts to be gathered. If not defined facts are gathered for all interfaces
    - Required: `False`
    - Type: `List`
        - Element-Type: `String`
    - Default: `None`
- `namespace` - shows external interfaces for a specific ASIC's namespace
    - Required: `False`
    - Type: `String`
    - Default: `None`
- `include_internal_intfs` - Whether or not to include internal interfaces
    - Required: `False`
    - Type: `Boolean`
    - Default: `False`

## Expected Output
Will return a dictionary describing either status or counters depending on argument provided. 

### status

The dictionary hierarchy is described below, with each indentation describing a sub-dictionary:
- `ansible_facts` - Dictionary that describes statuses
    - `int_status` - Dictionary that maps interface name to status info
        - `{INTERFACE_NAME}` - Dictionary containing status info on specified interface
            - `name` - Name of interface, same as provided
            - `speed` - Network speed of interface
            - `alias` - Interface's local alias
            - `vlan` - VLAN config type
            - `oper_state` - oper status
            - `admin_state` - admin status

### counter

The dictionary hierarchy is described below, with each indentation describing a sub-dictionary:

- `ansible_facts` - Dictionary that describes counters
    - `int_counter` - Dictionary that maps interface name to counter info
        - `{INTERFACE_NAME}` - Dictionary containing counter info on specified interface
            - `IFACE` - name of interface, same as provided
            - `STATE` - state of interface `U` or `D`
            - `RX_OK` - packets received ok
            - `RX_DRP` - Packets received dropped
            - `RX_OVR` - Packets interface was unable to recieve
            - `TX_OK` - Packets correctly transmitted
            - `TX_ERR` - Packets incorrectly transmitted
            - `TX_DRP` - Dropped Packets transmitted
            - `TX_OVR` - Packets unable to be transmitted