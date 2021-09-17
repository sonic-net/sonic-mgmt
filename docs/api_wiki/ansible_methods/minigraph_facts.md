# minigraph_facts

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Retrieve minigraph facts for a device.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    minigraph_info = duthost.minigraph_facts(host=duthost.hostname)
```

## Arguments
- `host` - hostname to get minigraph facts for
    - Required: `True`
    - Type: `String`
- `filename` - Path to minigraph.xml file to use for call
    - Required: `False`
    - Type: `String`
- `namespace` - name of desired ASIC for facts
    - Required: `False`
    - Type: `String`
    - Defulat: `None`

## Expected Output
A dictionary would be returned containing info on the minigraph. The dictionary hierarchy is described below, with each indentation describing a sub-dictionary:

- `ansible_facts` - Dictionary containing info on the minigraph
    - `minigraph_portchannel_interfaces` - List of dictionaries containing information on configured portchannel interfaces
        - `subnet` - subnet for portchannel
        - `peer_addr` - IP Address for portchannel
        - `attachto` - name of portchannel interface
        - `addr` - portchannel address
        - `prefixlen` - length of prefix
        - `mask` - subnet mask
    - `syslog_servers` - list of addresses corresponding to syslog
    - `minigraph_acls` - dictionary containing information on ACLs and their attached ports
        - `{ACL_TABLE_NAME}` - List of attached ports corresponding to provided ACL table name.
    - `forced_mgmt_routes` - ?
    - `minigraph_interfaces` - ?
    - `minigraph_port_name_to_alias_map` - dictionary that maps names of ports to their aliases
        - `{PORT_NAME}` - alias of the specified port
    - `minigraph_bgp` - list of dictionaries defining BGP neighbors
        - `addr` - BGP IP of neighbor
        - `peer_addr` - mgmt ip of neighbor
        - `asn` - neighbor asn
        - `name` - name of neighbor
    - `minigraph_portchannels` - Dictionary providing info on portchannel configuration
        - `{PORTCHANNEL_NAME}` - Dicitionary providing info on specified portchannel
            - `namespace` - ?
            - `name` - portchannel name (same as specified previously)
            - `members` - list of attached ports
    - `minigraph_bgp_peers_with_range` - list of dictionaries describing BGP peers
        - `name` - name of BGP peer
        - `ip_range` - list of ip ranges associated with peer
    - `minigraph_port_indices` - dictionary that maps port names to their index
        - `{PORT_NAME}` - the associated index
    - `minigraph_underlay_neighbors` - ?
    - `minigraph_as_xml` - location of minigraph config file
    - `minigraph_mgmt_interface` - Information on the configured management interface
        - `prefixlen` - length of prefix
        - `alias` - mgmt interface alias
        - `mask` - subnet mask
        - `addr` - mgmt interface address
        - `gwaddr` - ?
    - `minigraph_vlans` - Dictionary describing the configuration of the VLANs
        - `{VLAN_NAME}` - Dictionary describing config of specified VLAN
            - `type` - type of VLAN
            - `name` - VLAN name (same as specified previously)
            - `members` - list of interfaces attached to vlan
            - `vlanid` - numeric ID of VLAN
    - `deployment_id` - numeric id for minigraph deployment
    - `inventory_hostname` - ?
    - `minigraph_hostname` - hostname for device minigraph config is deployed on
    - `minigraph_console` - ?
    - `minigraph_device_metadata` - Dectionary providing info on the host described by `mingraph_hostname`
        - `bgp_asn` - asn for host
        - `deployment_id` - deployment id for currently deployed minigraph
        - `hostname` - hostname for host with minigraph deployed
        - `device_type` - type of device (e.g. 'ToRRouter')
        - `hwsku` - Hardware switch being used
    - `minigraph_console` - ?
    - `dhcp_servers` - list of ip addresses associated with DHCP servers
    - `minigraph_ports` - dictionary describing ports configured by minigraph
        - `{PORT_NAME}` - dictionary containing info on port
            - `alias` - port alias
            - `name` - name of port (same as specified previously)
    - `ntp_servers` - list of ip address used for NTP requests
    - `minigraph_port_alias_to_name_map` - dictionary that maps port aliases to port names
        - `{PORT_ALIAS}` - name of port corresponding to provided alias
    - `minigraph_lo_interfaces` - list of dictionaries describing looback interfaces configured by minigraph
        - `prefixlen` - length of prefix
        - `mask` - subnet mask
        - `name` - name of loopback interface
        - `addr` - address configured for interface
    - `minigraph_mgmt` - ?
    - `minigraph_underlay_devices` - ?
    - `minigraph_devices` - dictionary that maps device names to information on device corresponding to name
        - `{DEVICE_NAME}` - dictionary providing information corresponding to provided name
            - `lo_addr` - loopback address
            - `mgmt_addr` - mgmt address for specified device
            - `hwsku` - Type of hardware switch being used
            - `type` - type of device
    
    - `minigraph_bgp_asn` - BGP asn configured by minigraph
    - `minigraph_neighbors` - provides information on neighbor ports
        - `{PORT_NAME}` - Dictionary providing information on port
            - `namespace` - ?
            - `name` - name of port
            - `port` - name of interface attached to
    - `minigraph_vlan_interfaces` - List of dictionaries describing interfaces attached to VLANs
        - `prefixlen` - length of prefix
        - `subnet` - subnet for interface
        - `mask` - subnet mask
        - `addr` - address configured for interface
        - `attachto` - name of VLAN interface is attached to
    - `minigraph_hwsku` - type of hardware switch being used by `minigraph_hostname`