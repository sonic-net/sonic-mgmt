#!/usr/bin/env python
import calendar
import os
import sys
import socket
import struct
import traceback
import json
import copy
import ipaddr as ipaddress
from collections import defaultdict
from natsort import natsorted
from ansible.module_utils.port_utils import get_port_alias_to_name_map

from lxml import etree as ET
from lxml.etree import QName

DOCUMENTATION = '''
---
module: minigraph_facts
version_added: "1.9"
author: Guohan Lu (gulv@microsoft.com)
short_description: Retrive minigraph facts for a device.
description:
    - Retrieve minigraph facts for a device, the facts will be
      inserted to the ansible_facts key.
options:
    host:
        description:
            - Set to target snmp server (normally {{inventory_hostname}})
        required: true
'''

EXAMPLES = '''
# Gather minigraph facts
- name: Gathering minigraph facts about the device
  minigraph_facts: host={{ hostname }}
'''

ns = "Microsoft.Search.Autopilot.Evolution"
ns1 = "http://schemas.datacontract.org/2004/07/Microsoft.Search.Autopilot.Evolution"
ns2 = "Microsoft.Search.Autopilot.NetMux"
ns3 = "http://www.w3.org/2001/XMLSchema-instance"

ANSIBLE_USER_MINIGRAPH_PATH = os.path.expanduser('~/.ansible/minigraph')
ANSIBLE_LOCAL_MINIGRAPH_PATH = '{}.xml'
ANSIBLE_USER_MINIGRAPH_MAX_AGE = 86400  # 24-hours (in seconds)

class minigraph_encoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj,
                      (ipaddress.IPv4Network, ipaddress.IPv6Network, ipaddress.IPv4Address, ipaddress.IPv6Address)):
            return str(obj)
        return json.JSONEncoder.default(self, obj)


def parse_png(png, hname):
    neighbors = {}
    devices = {}
    neighbors_namespace = defaultdict(str)
    console_dev = ''
    console_port = ''
    mgmt_dev = ''
    mgmt_port = ''
    try:
        from sonic_py_common import multi_asic
        namespace_list = multi_asic.get_namespace_list()
    except ImportError:
        namespace_list = ['']

    for child in png:
        if child.tag == str(QName(ns, "DeviceInterfaceLinks")):
            for link in child.findall(str(QName(ns, "DeviceLinkBase"))):
                linktype = link.find(str(QName(ns, "ElementType"))).text
                if linktype != "DeviceInterfaceLink" and linktype != "UnderlayInterfaceLink":
                    continue

                enddevice = link.find(str(QName(ns, "EndDevice"))).text
                endport = link.find(str(QName(ns, "EndPort"))).text
                startdevice = link.find(str(QName(ns, "StartDevice"))).text
                startport = link.find(str(QName(ns, "StartPort"))).text

                if enddevice == hname:
                    if port_alias_to_name_map.has_key(endport):
                        endport = port_alias_to_name_map[endport]
                    if startdevice.lower() in namespace_list:
                        neighbors_namespace[endport] = startdevice.lower()
                    else:
                        neighbors[endport] = {'name': startdevice, 'port': startport, 'namespace':''}
                elif startdevice == hname:
                    if port_alias_to_name_map.has_key(startport):
                        startport = port_alias_to_name_map[startport]
                    if enddevice.lower() in namespace_list:
                        neighbors_namespace[startport] = enddevice.lower()
                    else:
                        neighbors[startport] = {'name': enddevice, 'port': endport, 'namespace':''}

        if child.tag == str(QName(ns, "Devices")):
            for device in child.findall(str(QName(ns, "Device"))):
                lo_addr = None
                # don't shadow type()
                d_type = None
                mgmt_addr = None
                hwsku = None
                if str(QName(ns3, "type")) in device.attrib:
                    d_type = device.attrib[str(QName(ns3, "type"))]

                for node in device:
                    if node.tag == str(QName(ns, "Address")):
                        lo_addr = node.find(str(QName(ns2, "IPPrefix"))).text.split('/')[0]
                    elif node.tag == str(QName(ns, "ManagementAddress")):
                        mgmt_addr = node.find(str(QName(ns2, "IPPrefix"))).text.split('/')[0]
                    elif node.tag == str(QName(ns, "Hostname")):
                        name = node.text
                    elif node.tag == str(QName(ns, "HwSku")):
                        hwsku = node.text

                if name.lower() in namespace_list:
                    continue

                devices[name] = {'lo_addr': lo_addr, 'type': d_type, 'mgmt_addr': mgmt_addr, 'hwsku': hwsku}

        if child.tag == str(QName(ns, "DeviceInterfaceLinks")):
            for if_link in child.findall(str(QName(ns, 'DeviceLinkBase'))):
                if str(QName(ns3, "type")) in if_link.attrib:
                    link_type = if_link.attrib[str(QName(ns3, "type"))]
                    if link_type == 'DeviceSerialLink':
                        for node in if_link:
                            if node.tag == str(QName(ns, "EndPort")):
                                console_port = node.text.split()[-1]
                            elif node.tag == str(QName(ns, "EndDevice")):
                                console_dev = node.text
                    elif link_type == 'DeviceMgmtLink':
                        for node in if_link:
                            if node.tag == str(QName(ns, "EndPort")):
                                mgmt_port = node.text.split()[-1]
                            elif node.tag == str(QName(ns, "EndDevice")):
                                mgmt_dev = node.text

    for k, v in neighbors.iteritems():
         v['namespace'] = neighbors_namespace[k]

    return (neighbors, devices, console_dev, console_port, mgmt_dev, mgmt_port)


def parse_dpg(dpg, hname):
    for child in dpg:
        hostname = child.find(str(QName(ns, "Hostname")))
        if hostname.text != hname:
            continue

        ipintfs = child.find(str(QName(ns, "IPInterfaces")))
        intfs = []
        for ipintf in ipintfs.findall(str(QName(ns, "IPInterface"))):
            intfalias = ipintf.find(str(QName(ns, "AttachTo"))).text
            if port_alias_to_name_map.has_key(intfalias):
                intfname = port_alias_to_name_map[intfalias]
            else:
                intfname = intfalias
            ipprefix = ipintf.find(str(QName(ns, "Prefix"))).text
            ipn = ipaddress.IPNetwork(ipprefix)
            ipaddr = ipn.ip
            prefix_len = ipn.prefixlen
            addr_bits = ipn.max_prefixlen
            subnet = ipaddress.IPNetwork(str(ipn.network) + '/' + str(prefix_len))
            ipmask = ipn.netmask

            intf = {'addr': ipaddr, 'subnet': subnet}
            if isinstance(ipn, ipaddress.IPv4Network):
                intf['mask'] = ipmask
            else:
                intf['mask'] = str(prefix_len)
            intf.update({'attachto': intfname, 'prefixlen': int(prefix_len)})

            # TODO: remove peer_addr after dependency removed
            ipaddr_val = int(ipn.ip)
            peer_addr_val = None
            if int(prefix_len) == addr_bits - 2:
                if ipaddr_val & 0x3 == 1:
                    peer_addr_val = ipaddr_val + 1
                else:
                    peer_addr_val = ipaddr_val - 1
            elif int(prefix_len) == addr_bits - 1:
                if ipaddr_val & 0x1 == 0:
                    peer_addr_val = ipaddr_val + 1
                else:
                    peer_addr_val = ipaddr_val - 1

            if peer_addr_val is not None:
                intf['peer_addr'] = ipaddress.IPAddress(peer_addr_val)
            intfs.append(intf)
            ports[intfname] = {'name': intfname, 'alias': intfalias}

        lointfs = child.find(str(QName(ns, "LoopbackIPInterfaces")))
        lo_intfs = []
        for lointf in lointfs.findall(str(QName(ns1, "LoopbackIPInterface"))):
            intfname = lointf.find(str(QName(ns, "AttachTo"))).text
            ipprefix = lointf.find(str(QName(ns1, "PrefixStr"))).text
            ipn = ipaddress.IPNetwork(ipprefix)
            ipaddr = ipn.ip
            prefix_len = ipn.prefixlen
            ipmask = ipn.netmask
            lo_intf = {'name': intfname, 'addr': ipaddr, 'prefixlen': prefix_len}
            if isinstance(ipn, ipaddress.IPv4Network):
                lo_intf['mask'] = ipmask
            else:
                lo_intf['mask'] = str(prefix_len)
            lo_intfs.append(lo_intf)

        mgmtintfs = child.find(str(QName(ns, "ManagementIPInterfaces")))
        mgmt_intf = None
        for mgmtintf in mgmtintfs.findall(str(QName(ns1, "ManagementIPInterface"))):
            intfname = mgmtintf.find(str(QName(ns, "AttachTo"))).text
            ipprefix = mgmtintf.find(str(QName(ns1, "PrefixStr"))).text
            mgmtipn = ipaddress.IPNetwork(ipprefix)
            # Ignore IPv6 management address
            if mgmtipn.version == 6:
                continue
            ipaddr = mgmtipn.ip
            prefix_len = str(mgmtipn.prefixlen)
            ipmask = mgmtipn.netmask
            gwaddr = ipaddress.IPAddress(int(mgmtipn.network) + 1)
            mgmt_intf = {'addr': ipaddr, 'alias': intfname, 'prefixlen': prefix_len, 'mask': ipmask, 'gwaddr': gwaddr}

        pcintfs = child.find(str(QName(ns, "PortChannelInterfaces")))
        pcs = {}
        for pcintf in pcintfs.findall(str(QName(ns, "PortChannel"))):
            pcintfname = pcintf.find(str(QName(ns, "Name"))).text
            pcintfmbr = pcintf.find(str(QName(ns, "AttachTo"))).text
            pcmbr_list = pcintfmbr.split(';', 1)
            for i, member in enumerate(pcmbr_list):
                pcmbr_list[i] = port_alias_to_name_map[member]
                ports[port_alias_to_name_map[member]] = {'name': port_alias_to_name_map[member], 'alias': member}
            pcs[pcintfname] = {'name': pcintfname, 'members': pcmbr_list}
            fallback_node = pcintf.find(str(QName(ns, "Fallback")))
            if fallback_node is not None:
                pcs[pcintfname]['fallback'] = fallback_node.text
            ports.pop(pcintfname, None)

        vlanintfs = child.find(str(QName(ns, "VlanInterfaces")))
        dhcp_servers = []
        vlans = {}
        for vintf in vlanintfs.findall(str(QName(ns, "VlanInterface"))):
            vintfname = vintf.find(str(QName(ns, "Name"))).text
            vlanid = vintf.find(str(QName(ns, "VlanID"))).text
            vintfmbr = vintf.find(str(QName(ns, "AttachTo"))).text
            vmbr_list = vintfmbr.split(';')
            vintf_node = vintf.find(str(QName(ns, "DhcpRelays")))
            if vintf_node is not None and vintf_node.text is not None:
                vlandhcpservers = vintf_node.text
            else:
                vlandhcpservers = ""
            dhcp_servers = vlandhcpservers.split(";")
            for i, member in enumerate(vmbr_list):
                # Skip PortChannel inside Vlan
                if member in pcs:
                    continue
                vmbr_list[i] = port_alias_to_name_map[member]
                ports[port_alias_to_name_map[member]] = {'name': port_alias_to_name_map[member], 'alias': member}
            vlan_attributes = {'name': vintfname, 'members': vmbr_list, 'vlanid': vlanid}
            vlans[vintfname] = vlan_attributes
            ports.pop(vintfname)

        aclintfs = child.find(str(QName(ns, "AclInterfaces")))
        acls = {}
        for aclintf in aclintfs.findall(str(QName(ns, "AclInterface"))):
            aclname = aclintf.find(str(QName(ns, "InAcl"))).text
            aclattach = aclintf.find(str(QName(ns, "AttachTo"))).text.split(';')
            acl_intfs = []
            for member in aclattach:
                member = member.strip()
                if pcs.has_key(member):
                    acl_intfs.extend(pcs[member]['members'])  # For ACL attaching to port channels, we break them into port channel members
                elif vlans.has_key(member):
                    print >> sys.stderr, "Warning: ACL " + aclname + " is attached to a Vlan interface, which is currently not supported"
                elif port_alias_to_name_map.has_key(member):
                    acl_intfs.append(port_alias_to_name_map[member])
            if acl_intfs:
                acls[aclname] = acl_intfs

        return intfs, lo_intfs, mgmt_intf, vlans, pcs, acls, dhcp_servers
    return None, None, None, None, None, None

def parse_cpg(cpg, hname):
    bgp_sessions = []
    myasn = None
    bgp_peers_with_range = []
    for child in cpg:
        tag = child.tag
        if tag == str(QName(ns, "PeeringSessions")):
            for session in child.findall(str(QName(ns, "BGPSession"))):
                start_router = session.find(str(QName(ns, "StartRouter"))).text
                start_peer = session.find(str(QName(ns, "StartPeer"))).text
                end_router = session.find(str(QName(ns, "EndRouter"))).text
                end_peer = session.find(str(QName(ns, "EndPeer"))).text
                if end_router == hname:
                    bgp_sessions.append({
                        'name': start_router,
                        'addr': start_peer,
                        'peer_addr': end_peer
                    })
                else:
                    bgp_sessions.append({
                        'name': end_router,
                        'addr': end_peer,
                        'peer_addr': start_peer
                    })
        elif child.tag == str(QName(ns, "Routers")):
            for router in child.findall(str(QName(ns1, "BGPRouterDeclaration"))):
                asn = router.find(str(QName(ns1, "ASN"))).text
                hostname = router.find(str(QName(ns1, "Hostname"))).text
                if hostname == hname:
                    myasn = int(asn)
                    peers = router.find(str(QName(ns1, "Peers")))
                    for bgpPeer in peers.findall(str(QName(ns, "BGPPeer"))):
                        addr = bgpPeer.find(str(QName(ns, "Address"))).text
                        if bgpPeer.find(str(QName(ns1, "PeersRange"))) is not None:
                            name = bgpPeer.find(str(QName(ns1, "Name"))).text
                            ip_range = bgpPeer.find(str(QName(ns1, "PeersRange"))).text
                            ip_range_group = ip_range.split(';') if ip_range and ip_range != "" else []
                            bgp_peers_with_range.append({
                                'name': name,
                                'ip_range': ip_range_group
                            })

                else:
                    for bgp_session in bgp_sessions:
                        if hostname == bgp_session['name']:
                            bgp_session['asn'] = int(asn)

    return bgp_sessions, myasn, bgp_peers_with_range


def parse_meta(meta, hname):
    syslog_servers = []
    ntp_servers = []
    mgmt_routes = []
    deployment_id = None
    device_metas = meta.find(str(QName(ns, "Devices")))
    for device in device_metas.findall(str(QName(ns1, "DeviceMetadata"))):
        if device.find(str(QName(ns1, "Name"))).text == hname:
            properties = device.find(str(QName(ns1, "Properties")))
            for device_property in properties.findall(str(QName(ns1, "DeviceProperty"))):
                name = device_property.find(str(QName(ns1, "Name"))).text
                value = device_property.find(str(QName(ns1, "Value"))).text
                value_group = value.split(';') if value and value != "" else []
                if name == "NtpResources":
                    ntp_servers = value_group
                elif name == "SyslogResources":
                    syslog_servers = value_group
                elif name == "ForcedMgmtRoutes":
                    mgmt_routes = value_group
                elif name == "DeploymentId":
                    deployment_id = value
    return syslog_servers, ntp_servers, mgmt_routes, deployment_id


def get_console_info(devices, dev, port):
    for k, v in devices.items():
        if k == dev:
            break
    else:
        return {}

    ret_val = v
    ret_val.update({
        'ts_port': port,
        'ts_dev': dev
    })

    return ret_val


def get_mgmt_info(devices, dev, port):
    for k, v in devices.items():
        if k == dev:
            break
    else:
        return {}

    ret_val = v
    ret_val.update({
        'mgmt_port': port,
        'mgmt_dev': dev
    })

    return ret_val


def file_age(filename):
    """
    :param filename: The filename to carbon date.
    :return: The age of the file in seconds.
    """
    return calendar.timegm(time.gmtime()) - os.path.getctime(filename)


def reconcile_mini_graph_locations(filename, hostname):
    """
    Location precedence:
    1. "filename" module parameter
    2. minigraph/ folder
    3. .ansible/minigraph/ folder (<24 hrs old)
    4. Network Graph Service

    post-download, cache to the user folder:
    ~/.ansible/minigraph/HOSTNAME_minigraph.xml

    :param filename: the filename to load (may be None)
    :param hostname: the hostname to load (required)
    :return: tuple(the absolute filepath of the {cached,loaded} mini-graph, the root node of the loaded graph)
    """
    if filename is not None:
        # literal filename specified. read directly from the file.
        mini_graph_path = filename
    else:
        # only the hostname was specified, determine the output path
        mini_graph_path = '/etc/sonic/minigraph.xml'

    root = ET.parse(mini_graph_path).getroot()
    return mini_graph_path, root

def port_alias_to_name_map_50G(all_ports, s100G_ports):
    # 50G ports
    s50G_ports = list(set(all_ports) - set(s100G_ports))

    for i in s50G_ports:
        port_alias_to_name_map["Ethernet%d/1" % i] = "Ethernet%d" % ((i - 1) * 4)
        port_alias_to_name_map["Ethernet%d/3" % i] = "Ethernet%d" % ((i - 1) * 4 + 2)

    for i in s100G_ports:
        port_alias_to_name_map["Ethernet%d/1" % i] = "Ethernet%d" % ((i - 1) * 4)

    return port_alias_to_name_map

def parse_xml(filename, hostname):
    mini_graph_path, root = reconcile_mini_graph_locations(filename, hostname)

    u_neighbors = None
    u_devices = None
    hwsku = None
    bgp_sessions = None
    bgp_asn = None
    intfs = None
    vlan_intfs = None
    pc_intfs = None
    vlans = None
    pcs = None
    mgmt_intf = None
    lo_intf = None
    neighbors = None
    devices = None
    hostname = None
    syslog_servers = []
    dhcp_servers = []
    ntp_servers = []
    mgmt_routes = []
    bgp_peers_with_range = []
    deployment_id = None

    hwsku_qn = QName(ns, "HwSku")
    hostname_qn = QName(ns, "Hostname")
    for child in root:
        if child.tag == str(hwsku_qn):
            hwsku = child.text
        if child.tag == str(hostname_qn):
            hostname = child.text

    global port_alias_to_name_map

    port_alias_to_name_map = get_port_alias_to_name_map(hwsku)

    for child in root:
        if child.tag == str(QName(ns, "DpgDec")):
            (intfs, lo_intfs, mgmt_intf, vlans, pcs, acls, dhcp_servers) = parse_dpg(child, hostname)
        elif child.tag == str(QName(ns, "CpgDec")):
            (bgp_sessions, bgp_asn, bgp_peers_with_range) = parse_cpg(child, hostname)
        elif child.tag == str(QName(ns, "PngDec")):
            (neighbors, devices, console_dev, console_port, mgmt_dev, mgmt_port) = parse_png(child, hostname)
        elif child.tag == str(QName(ns, "UngDec")):
            (u_neighbors, u_devices, _, _, _, _) = parse_png(child, hostname)
        elif child.tag == str(QName(ns, "MetadataDeclaration")):
            (syslog_servers, ntp_servers, mgmt_routes, deployment_id) = parse_meta(child, hostname)

    # TODO: Move all alias-related code out of minigraph_facts.py and into
    # its own module to be used as another layer after parsing the minigraph.

    # Create inverse mapping between port name and alias
    port_name_to_alias_map = {v: k for k, v in port_alias_to_name_map.iteritems()}

    # Create a map of SONiC port name to physical port index
    # Start by creating a list of all port names
    port_name_list = port_name_to_alias_map.keys()

    # Sort the list in natural order, because SONiC port names, when
    # sorted in natural sort order, match the phyical port index order
    port_name_list_sorted = natsorted(port_name_list)

    # Create mapping between port alias and physical index
    port_index_map = {}
    for idx, val in enumerate(port_name_list_sorted):
        port_index_map[val] = idx

    # Generate results
    Tree = lambda: defaultdict(Tree)

    results = Tree()
    results['minigraph_hwsku'] = hwsku
    # sorting by lambdas are not easily done without custom filters.
    # TODO: add jinja2 filter to accept a lambda to sort a list of dictionaries by attribute.
    # TODO: alternatively (preferred), implement class containers for multiple-attribute entries, enabling sort by attr
    results['minigraph_bgp'] = sorted(bgp_sessions, key=lambda x: x['addr'])
    results['minigraph_bgp_asn'] = bgp_asn
    results['minigraph_bgp_peers_with_range'] = bgp_peers_with_range
    # TODO: sort does not work properly on all interfaces of varying lengths. Need to sort by integer group(s).

    phyport_intfs = []
    vlan_intfs = []
    pc_intfs = []
    for intf in intfs:
        intfname = intf['attachto']
        if intfname[0:4] == 'Vlan':
            vlan_intfs.append(intf)
        elif intfname[0:11] == 'PortChannel':
            pc_intfs.append(intf)
        else:
            phyport_intfs.append(intf)

    results['minigraph_interfaces'] = sorted(phyport_intfs, key=lambda x: x['attachto'])
    results['minigraph_vlan_interfaces'] = sorted(vlan_intfs, key=lambda x: x['attachto'])
    results['minigraph_portchannel_interfaces'] = sorted(pc_intfs, key=lambda x: x['attachto'])
    results['minigraph_ports'] = ports
    results['minigraph_vlans'] = vlans
    results['minigraph_portchannels'] = pcs
    results['minigraph_mgmt_interface'] = mgmt_intf
    results['minigraph_lo_interfaces'] = lo_intfs
    results['minigraph_acls'] = acls
    results['minigraph_neighbors'] = neighbors
    results['minigraph_devices'] = devices
    results['minigraph_underlay_neighbors'] = u_neighbors
    results['minigraph_underlay_devices'] = u_devices
    results['minigraph_port_indices'] = port_index_map
    results['minigraph_port_name_to_alias_map'] = port_name_to_alias_map
    results['minigraph_port_alias_to_name_map'] = port_alias_to_name_map
    results['minigraph_as_xml'] = mini_graph_path
    if devices != None:
        results['minigraph_console'] = get_console_info(devices, console_dev, console_port)
        results['minigraph_mgmt'] = get_mgmt_info(devices, mgmt_dev, mgmt_port)
    results['minigraph_hostname'] = hostname
    results['inventory_hostname'] = hostname
    results['syslog_servers'] = syslog_servers
    results['dhcp_servers'] = dhcp_servers
    results['ntp_servers'] = ntp_servers
    results['forced_mgmt_routes'] = mgmt_routes
    results['deployment_id'] = deployment_id
    return results

ports = {}
port_alias_to_name_map = {}

def main():
    module = AnsibleModule(
        argument_spec=dict(
            host=dict(required=True),
            filename=dict(),
        ),
        supports_check_mode=True
    )

    try:
        # make the directory for caching the mini-graph.
        os.makedirs(ANSIBLE_USER_MINIGRAPH_PATH)
    except OSError:
        if not os.path.isdir(ANSIBLE_USER_MINIGRAPH_PATH):
            # file conflict, report the error and exit.
            module.fail_json(msg="Cannot create dir: {}".format(ANSIBLE_USER_MINIGRAPH_PATH))

    m_args = module.params
    local_file_path = ANSIBLE_LOCAL_MINIGRAPH_PATH.format(m_args['host'])
    if 'filename' in m_args and m_args['filename'] is not None:
        # literal filename specified
        filename = "%s" % m_args['filename']
    elif os.path.exists(local_file_path):
        # local project minigraph found for the hostname, use that file
        filename = local_file_path
    else:
        # no file could be found
        filename = None

    try:
        results = parse_xml(filename, m_args['host'])
        results_clean = json.loads(json.dumps(results, cls=minigraph_encoder))
        module.exit_json(ansible_facts=results_clean)
    except Exception as e:
        tb = traceback.format_exc()
        # all attempts to find a minigraph failed.
        module.fail_json(msg=e.message + "\n" + tb)


def print_parse_xml(hostname):
    filename = hostname + '.xml'
    results = parse_xml(filename, hostname)
    print(json.dumps(results, indent=3, cls=minigraph_encoder))

from ansible.module_utils.basic import *

if __name__ == "__main__":
    main()
