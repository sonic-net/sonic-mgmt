# conn_graph_facts

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Retreives info on lab fannout siwtches and vlan connections.

## Examples
```
def test_fun(localhost):
    graph_facts = localhost.conn_graph_facts()
```

## Arguments
- `host` - the fannout switch name, the server name, or the SONiC switch name
    - Required: `False`
    - Type: `String`
- `hosts` - List of hosts
    - Required: `False`
    - Type: `List`
        - Element-Type: `String`
- `anchor` - List of hosts. When no host and hosts is provided, the anchor option must be specified with list of hosts. This option is to supply the relevant list of hosts for looking up the connection graph xml file which has all the supplied hosts. The whole graph will be returned when this option is used. This is for configuring the root fanout switch.
    - Required: `False`
    - Type: `List`
        - Element-Type: `String`
- `filepath` - Path to the connection graph xml file. Overrides default.
    - Required: `False`
    - Type: `String`
- `filename` - name of the connection graph xml file.
    - Required: `False`
    - Type: `String`

`host`, `hosts`, and `anchor` are mutually exclusive.

## Expected Output

- `device_info` - The device(host) type and hwsku
- `device_conn` - each physical connection of the device(host)
- `device_vlan_range` - all configured vlan range for the device(host)
- `device_port_vlans` - detailed vlanids for each physical port and switchport mode
- `server_links` - each server port vlan ids
- `device_console_info` - The device's console server type, mgmtip, hwsku and protocol
- `device_console_link` - The console server port connected to the device
- `device_pdu_info` - The device's pdu server type, mgmtip, hwsku and protocol
- `device_pdu_links` - The pdu server ports connected to the device

