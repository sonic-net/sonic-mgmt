# get_extended_minigraph_facts

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Gets detailed facts on configured minigraph.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname, tbinfo):
    duthost = duthosts[rand_one_dut_hostname]

    ext_minig_facts = duthost.get_extended_minigraph_facts(tbinfo)
```

## Arguments
- `tbinfo` - Testbed info dictionary
    - Required: `True`
    - Type: `Dictionary`
- `namespace` - namespace for desired ASIC
    - Required: `False`
    - Type: `String`
    - Default: `None`

## Expected Output
Returns a dictionary with a lot of information about the minigraph. The dictionary hierarchy is described below, with each indentation describing a sub-dictionary:

- `minigraph_portchannel_interfaces` - list of dictionaries that provide information on portchannel interfaces confgiured by minigraph
    - `subnet` - portchannel subnet
    - `peer_addr` - address for peer connected by portchannel
    - `attachto` - name of portchannel
    - `addr` - portchannel address
    - `prefixlen` - length of prefix
    - `mask` - subnet mask
- `syslog_servers` - list of addresses aossiciated with syslog
- `minigraph_acls` - Dictionary that maps ACL table names to their attached interfaces
    - `{ACL_TABLE_NAME}` - List of interfaces attacehd to provided ACL table
- `forced_mgmt_routes`
- `minigraph_interfaces`
- `minigraph_port_name_to_alias_map` - Dictionary that maps port names to their alias
    - `{PORT_NAME}` - alias associated with provided port name
- `minigraph_bgp` - List of dictionaries, each associated with a BGP neighbor
    - `addr` - address for BGP neighbor
    - `peer_addr` - address for associated portchannel
    - `asn` - Neighbors ASN
    - `name` - neighbors name
- `minigraph_portchannels` - Maps portchannel names to their configuration
    - `{PORTCHANNEL_NAME}` - Provides config info on provided portchannel
        - `namespace`
        - `name` - portchannel name (same as provided)
        - `members` - list of ports attached to portchannel
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

(u'minigraph_port_indices', {u'Ethernet8': 2})

(u'minigraph_underlay_neighbors', None)

(u'minigraph_as_xml', u'/etc/sonic/minigraph.xml')

(u'minigraph_mgmt_interface', {u'prefixlen': u'24', u'alias': u'eth0', u'mask': u'255.255.255.0', u'addr': u'10.250.0.101', u'gwaddr': u'10.250.0.1'})

(u'minigraph_vlans', {u'Vlan1000': {u'name': u'Vlan1000', u'members': [u'Ethernet4'], u'vlanid': u'1000'}})

(u'deployment_id', u'1')

(u'inventory_hostname', u'vlab-01')

(u'minigraph_hostname', u'vlab-01')

(u'minigraph_console', {})

('minigraph_ptf_indices', {u'Ethernet8': 2})

(u'minigraph_device_metadata', {u'bgp_asn': 65100, u'deployment_id': u'1', u'hostname': u'vlab-01', u'device_type': u'ToRRouter', u'hwsku': u'Force10-S6000'})

(u'dhcp_servers', [u'192.0.0.1', u'192.0.0.2', u'192.0.0.3', u'192.0.0.4'])

(u'minigraph_ports', {u'Ethernet28': {u'alias': u'fortyGigE0/28', u'name': u'Ethernet28'}})

(u'ntp_servers', [u'10.0.0.1', u'10.0.0.2'])

(u'minigraph_port_alias_to_name_map', {u'fortyGigE0/24': u'Ethernet24'})

(u'minigraph_lo_interfaces', [{u'prefixlen': 32, u'mask': u'255.255.255.255', u'name': u'Loopback0', u'addr': u'10.1.0.32'}, {u'prefixlen': 128, u'mask': u'128', u'name': u'Loopback0', u'addr': u'fc00:1::32'}])

(u'minigraph_mgmt', {})

(u'minigraph_underlay_devices', None)

(u'minigraph_devices', {u'vlab-01': {u'lo_addr': None, u'mgmt_addr': u'10.250.0.101', u'hwsku': u'Force10-S6000', u'type': u'ToRRouter'}}})

(u'minigraph_bgp_asn', 65100)

(u'minigraph_neighbors', {u'Ethernet28': {u'namespace': u'', u'name': u'Servers6', u'port': u'eth0'}})

(u'minigraph_vlan_interfaces', [{u'prefixlen': 21, u'subnet': u'192.168.0.0/21', u'mask': u'255.255.248.0', u'addr': u'192.168.0.1', u'attachto': u'Vlan1000'}, {u'prefixlen': 64, u'subnet': u'fc02:1000::/64', u'mask': u'64', u'addr': u'fc02:1000::1', u'attachto': u'Vlan1000'}])