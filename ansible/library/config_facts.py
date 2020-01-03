#!/usr/bin/env python
import json
import ipaddr as ipaddress
from collections import defaultdict
from natsort import natsorted

DOCUMENTATION = '''
---
module: config_facts
version_added: "1.0"
author: Mykola Faryma (mykolaf@mellanox.com)
short_description: Retrive configuration facts for a device.
description:
    - Retrieve configuration facts for a device, the facts will be
      inserted to the ansible_facts key.
    - The data can be pulled from redis (running config) or /etc/sonic/config_db.json (persistent config)
options:
    host:
        description:
            - Set to target switch (normally {{inventory_hostname}})
        required: true
    source:
        description:
            - Set to "running" for running config, or "persistent" for persistent config from /etc/sonic/config_db.json
'''

PERSISTENT_CONFIG_PATH = "/etc/sonic/config_db.json"

def parse_meta_servers(config):
    dhcp_servers = []
    ntp_servers = []

    if "DHCP_SERVER" in config:
        dhcp_servers = config["DHCP_SERVER"].keys()

    if "NTP_SERVER" in config:
        dhcp_servers = config["NTP_SERVER"].keys()

    return dhcp_servers, ntp_servers

def parse_meta(config):

    localhost_config = config['DEVICE_METADATA']['localhost']

    hostname = localhost_config.get('hostname', None)
    hwsku = localhost_config.get('hwsku', None)
    deployment_id = localhost_config.get('deployment_id', None)
    bgp_asn = localhost_config.get('bgp_asn', None)
    mac = localhost_config.get('mac', None)
    platform = localhost_config.get('platform', None)

    return hostname, hwsku, deployment_id, bgp_asn, mac, platform

def parse_bgp(config):

    bgp_sessions = []
    bgp_peers_with_range = []

    try:
        for addr in config["BGP_NEIGHBOR"]:
            bgp_sessions.append({
                'name': config["BGP_NEIGHBOR"][addr]['name'],
                'addr': addr,
                'peer_addr': config["BGP_NEIGHBOR"][addr]['local_addr'],
                'asn' : int(config["BGP_NEIGHBOR"][addr]['asn'])
            })

        for peer_range in config["BGP_PEER_RANGE"].values():
            bgp_peers_with_range.append({
                'name': peer_range['name'],
                'ip_range' : peer_range['ip_range']
            })
    except KeyError:
        pass

    return bgp_sessions, bgp_peers_with_range


def parse_interfaces(config):
    router_intfs = []
    vlan_intfs = []
    pc_intfs = []
    lo_intfs = []
    mgmt_intfs = {}

    if "INTERFACE" in config:
        for entry in config["INTERFACE"].keys():
            if '|' not in entry: 
                continue
            interface_name, subnet = entry.split('|')
            subnet = ipaddress.IPNetwork(subnet)
            router_intfs.append({
                'name' : interface_name,
                'attachto' : interface_name,
                'subnet' : str(subnet),
                'addr' : str(subnet.ip),
                'prefixlen' : subnet.prefixlen,
                'mask' : str(subnet.netmask)
            })
    if "VLAN_INTERFACE" in config:
        for entry in config["VLAN_INTERFACE"].keys():
            if '|' not in entry: 
                continue
            vlan_name, subnet = entry.split('|')
            subnet = ipaddress.IPNetwork(subnet)
            vlan_intfs.append({
                'name' : vlan_name,
                'attachto' : vlan_name,
                'subnet' : str(subnet),
                'addr' : str(subnet.ip),
                'prefixlen' : subnet.prefixlen,
                'mask' : str(subnet.netmask)
            })
    if "PORTCHANNEL_INTERFACE" in config:
        for entry in config["PORTCHANNEL_INTERFACE"].keys():
            if '|' not in entry: 
                continue
            pc_name, subnet = entry.split('|')
            subnet = ipaddress.IPNetwork(subnet)
            pc_intfs.append({
                'name' : pc_name,
                'attachto' : pc_name,
                'subnet' : str(subnet),
                'addr' : str(subnet.ip),
                'prefixlen' : subnet.prefixlen,
                'mask' : str(subnet.netmask)
            })

    if "MGMT_INTERFACE" in config:
        for entry, v in config["MGMT_INTERFACE"].iteritems():
            if '|' not in entry: 
                continue
            interface_name, subnet = entry.split('|')
            # Looking for IPv4 mgmt interface here
            try:
                subnet = ipaddress.IPNetwork(subnet, version=4)
            except ValueError:
                continue
            mgmt_intfs = {
                'name' : interface_name,
                'alias' : interface_name,
                'subnet' : str(subnet),
                'addr' : str(subnet.ip),
                'prefixlen' : subnet.prefixlen,
                'mask' : str(subnet.netmask),
                'gwaddr' : v['gwaddr']
            }

    if "LOOPBACK_INTERFACE" in config:
        for entry, v in config["LOOPBACK_INTERFACE"].iteritems():
            if '|' not in entry: 
                continue
            interface_name, subnet = entry.split('|')
            subnet = ipaddress.IPNetwork(subnet)
            lo_intfs.append({
                'name' : interface_name,
                'subnet' : str(subnet),
                'addr' : str(subnet.ip),
                'prefixlen' : subnet.prefixlen,
                'mask' : str(subnet.netmask),
            })

    return router_intfs, vlan_intfs, pc_intfs, lo_intfs, mgmt_intfs


def parse_ports(config):
    ports = {}
    portchannels = {}
    vlans = {}

    if "PORT" in config:
        for k, v in config["PORT"].items():
            ports[k] = {
                'alias' : v['alias'],
                'speed' : v['speed'],
                'admin_status' : v.get('admin_status', 'down'),
                'name' : k
            }
    if "VLAN" in config:
        for k, v in config["VLAN"].items():
            vlans[k] = {
                'vlanid' : v['vlanid'],
                'name' : k,
                'members' : [ entry.split('|')[-1] for entry in config["VLAN_MEMBER"] if k in entry ]
            }
    if "PORTCHANNEL" in config:
        for k, v in config["PORTCHANNEL"].items():
            portchannels[k] = {
                'admin_status' : v.get('admin_status', 'down'),
                'name' : k,
                'members' : v['members']
            }

    return ports, vlans, portchannels

def create_alias_maps(config):
    # Create a map of SONiC port name to physical port index
    # Start by creating a list of all port names
    port_name_list = config["PORT"].keys()
    port_name_list_sorted = natsorted(port_name_list)

    port_index_map = {}
    for idx, val in enumerate(port_name_list_sorted):
        port_index_map[val] = idx

    port_name_to_alias_map = { name : v['alias'] for name, v in config["PORT"].iteritems()}

    # Create inverse mapping between port name and alias
    port_alias_to_name_map = {v: k for k, v in port_name_to_alias_map.iteritems()}

    return port_name_to_alias_map, port_alias_to_name_map, port_index_map


def parse_acl(config):
    return config.get('ACL_TABLE', {})


def parse_devices(config):

    devices = config.get('DEVICE_NEIGHBOR', {})
    neighbors = config.get('DEVICE_NEIGHBOR_METADATA', {})
    return devices, neighbors


def get_running_config(module):

    rt, out, err = module.run_command("sonic-cfggen -d --print-data")
    if rt != 0:
        module.fail_json(msg="failed to dump running config!")
    json_info = json.loads(out)
    return json_info


def parse_config(config):

    # Generate results
    Tree = lambda: defaultdict(Tree)

    results = Tree()
    hostname, hwsku, deployment_id, bgp_asn, mac, platform = parse_meta(config)
    results['config_hwsku'] = hwsku
    results['deployment_id'] = deployment_id
    results['config_hostname'] = hostname
    results['inventory_hostname'] = hostname
    results['config_bgp_asn'] = bgp_asn

    bgp_sessions, bgp_peers_with_range = parse_bgp(config)
    results['config_bgp'] = bgp_sessions
    results['config_bgp_peers_with_range'] = bgp_peers_with_range

    router_intfs, vlan_intfs, pc_intfs, lo_intfs, mgmt_intfs = parse_interfaces(config)
    results['config_interfaces'] = sorted(router_intfs, key=lambda x: x['name'])
    results['config_vlan_interfaces'] = sorted(vlan_intfs, key=lambda x: x['name'])
    results['config_portchannel_interfaces'] = sorted(pc_intfs, key=lambda x: x['name'])
    results['config_mgmt_interface'] = mgmt_intfs
    results['config_lo_interfaces'] = lo_intfs

    ports, vlans, portchannels = parse_ports(config)
    results['config_ports'] = ports
    results['config_vlans'] = vlans
    results['config_portchannels'] = portchannels

    results['config_acls'] = parse_acl(config)

    port_name_to_alias_map, port_alias_to_name_map, port_index_map = create_alias_maps(config)
    results['config_port_indices'] = port_index_map
    results['config_port_name_to_alias_map'] = port_name_to_alias_map
    results['config_port_alias_to_name_map'] = port_alias_to_name_map

    devices, neighbors = parse_devices(config)
    results['config_neighbors'] = neighbors
    results['config_devices'] = devices

    dhcp_servers, ntp_servers = parse_meta_servers(config) 
    results['dhcp_servers'] = dhcp_servers
    results['ntp_servers'] = ntp_servers

    return results

def main():
    module = AnsibleModule(
        argument_spec=dict(
            host=dict(required=True),
            source=dict(required=True, choices=["running", "persistent"]),
            filename=dict(),
        ),
        supports_check_mode=True
    )

    m_args = module.params
    try:
        config = {}
        if m_args["source"] == "persistent":
            with open(PERSISTENT_CONFIG_PATH, "r") as f:
                config = json.load(f)
        elif m_args["source"] == "running":    
            config = get_running_config(module)

        results = parse_config(config)
        module.exit_json(ansible_facts=results)
    except Exception as e:
        module.fail_json(msg=e.message)


from ansible.module_utils.basic import *

if __name__ == "__main__":
    main()
