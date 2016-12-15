#!/usr/bin/env python
import calendar
import os
import sys
import socket
import struct
import json
import copy
import ipaddr as ipaddress
from collections import defaultdict


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
ANSIBLE_LOCAL_MINIGRAPH_PATH = 'minigraph/{}.xml'
ANSIBLE_USER_MINIGRAPH_MAX_AGE = 86400  # 24-hours (in seconds)

class minigraph_encoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (ipaddress.IPv4Network, ipaddress.IPv6Network, ipaddress.IPv4Address, ipaddress.IPv6Address)):
            return str(obj)
        return json.JSONEncoder.default(self, obj)
        
def parse_png(png, hname):
    neighbors = {}
    devices = {}
    console_dev = ''
    console_port = ''
    mgmt_dev = ''
    mgmt_port = ''
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
                    neighbors[endport] = {'name': startdevice, 'port': startport}
                else:
                    neighbors[startport] = {'name': enddevice, 'port': endport}
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


    return (neighbors, devices, console_dev, console_port, mgmt_dev, mgmt_port)


def parse_dpg(dpg, hname):
    for child in dpg:
        hostname = child.find(str(QName(ns, "Hostname")))
        if hostname.text != hname:
            continue

        ipintfs = child.find(str(QName(ns, "IPInterfaces")))
        intfs = []
        vlan_map = {}
        for ipintf in ipintfs.findall(str(QName(ns, "IPInterface"))):
            intfname = ipintf.find(str(QName(ns, "AttachTo"))).text
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
                    
            if intfname[0:4] == "Vlan":
                if intfname in vlan_map:
                    vlan_map[intfname].append(intf)
                    
                else:
                    vlan_map[intfname] = [intf]
            else:
                intf.update({'name': intfname, 'prefixlen': int(prefix_len)})
                    
                if port_alias_map.has_key(intfname):
                    intf['alias'] = port_alias_map[intfname]
                else:
                    intf['alias'] = intfname
                    
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

        pcintfs = child.find(str(QName(ns, "PortChannelInterfaces")))
        pc_intfs = []
        for pcintf in pcintfs.findall(str(QName(ns, "PortChannel"))):
            pcintfname = pcintf.find(str(QName(ns, "Name"))).text
            pcintfmbr = pcintf.find(str(QName(ns, "AttachTo"))).text
            mbr_list = pcintfmbr.split(';', 1)
            pc_intfs.append({'name': pcintfname, 'members': mbr_list})

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
            ipprefix = mgmtintf.find(str(QName(ns1, "PrefixStr"))).text
            mgmtipn = ipaddress.IPNetwork(ipprefix)
            ipaddr = mgmtipn.ip
            prefix_len = str(mgmtipn.prefixlen)
            ipmask = mgmtipn.netmask
            gwaddr = ipaddress.IPAddress(int(mgmtipn.network) + 1)
            mgmt_intf = {'addr': ipaddr, 'prefixlen': prefix_len, 'mask': ipmask, 'gwaddr': gwaddr}

        vlanintfs = child.find(str(QName(ns, "VlanInterfaces")))
        vlan_intfs = []
        for vintf in vlanintfs.findall(str(QName(ns, "VlanInterface"))):
            vintfname = vintf.find(str(QName(ns, "Name"))).text
            vlanid = vintf.find(str(QName(ns, "VlanID"))).text
            members = vintf.find(str(QName(ns, "AttachTo"))).text
            members = " ".join(members.split(';'))
            vlan_attributes = {'name': vintfname, 'members': members, 'vlanid': vlanid}
            for addrtuple in vlan_map.get(vintfname, []):
                vlan_attributes.update(addrtuple)
                vlan_intfs.append(copy.deepcopy(vlan_attributes))
                
        return intfs, lo_intfs, mgmt_intf, vlan_intfs, pc_intfs
    return None, None, None, None, None

def parse_cpg(cpg, hname):
    bgp_sessions = []
    myasn = None
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
                else:
                    for bgp_session in bgp_sessions:
                        if hostname == bgp_session['name']:
                            bgp_session['asn'] = int(asn)

    return bgp_sessions, myasn


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

    post-NGS download, cache to the user folder:
    ~/.ansible/minigraph/HOSTNAME_minigraph.xml

    :param filename: the filename to load (may be None)
    :param hostname: the hostname to load (required)
    :return: tuple(the absolute filepath of the {cached,loaded} mini-graph, the root node of the loaded graph)
    """
    if filename is not None:
        # literal filename specified. read directly from the file.
        root = ET.parse(filename).getroot()
        mini_graph_path = filename
    else:
        # only the hostname was specified, determine the output path
        mini_graph_path = os.path.join(ANSIBLE_USER_MINIGRAPH_PATH, hostname + '_minigraph.xml')
        if os.path.exists(mini_graph_path) and file_age(mini_graph_path) < ANSIBLE_USER_MINIGRAPH_MAX_AGE:
            # found a cached mini-graph, load it.
            root = ET.parse(mini_graph_path).getroot()

    return mini_graph_path, root


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
    mgmt_intf = None
    lo_intf = None
    neighbors = None
    devices = None

    hwsku_qn = QName(ns, "HwSku")
    for child in root:
        if child.tag == str(hwsku_qn):
            hwsku = child.text

    # port_alias_map maps ngs port name to sonic port name
    if hwsku == "Force10-S6000":
        for i in range(0, 128, 4):
            port_alias_map["fortyGigE0/%d" % i] = "Ethernet%d" % i
    elif hwsku == "Arista-7050-QX32":
        for i in range(1, 25):
            port_alias_map["Ethernet%d/1" % i] = "Ethernet%d" % ((i - 1) * 4)
        for i in range(25, 33):
            port_alias_map["Ethernet%d" % i] = "Ethernet%d" % ((i - 1) * 4)

    for child in root:
        if child.tag == str(QName(ns, "DpgDec")):
            (intfs, lo_intfs, mgmt_intf, vlan_intfs, pc_intfs) = parse_dpg(child, hostname)
        elif child.tag == str(QName(ns, "CpgDec")):
            (bgp_sessions, bgp_asn) = parse_cpg(child, hostname)
        elif child.tag == str(QName(ns, "PngDec")):
            (neighbors, devices, console_dev, console_port, mgmt_dev, mgmt_port) = parse_png(child, hostname)
        elif child.tag == str(QName(ns, "UngDec")):
            (u_neighbors, u_devices, _, _, _, _) = parse_png(child, hostname)

    # Replace port with alias in port channel interfaces members
    for pc in pc_intfs:
        for i,member in enumerate(pc['members']):
            pc['members'][i] = port_alias_map[member]

    Tree = lambda: defaultdict(Tree)

    results = Tree()
    results['minigraph_hwsku'] = hwsku
    # sorting by lambdas are not easily done without custom filters.
    # TODO: add jinja2 filter to accept a lambda to sort a list of dictionaries by attribute.
    # TODO: alternatively (preferred), implement class containers for multiple-attribute entries, enabling sort by attr
    results['minigraph_bgp'] = sorted(bgp_sessions, key=lambda x: x['addr'])
    results['minigraph_bgp_asn'] = bgp_asn
    # TODO: sort does not work properly on all interfaces of varying lengths. Need to sort by integer group(s).
    results['minigraph_interfaces'] = sorted(intfs, key=lambda x: x['name'])
    results['minigraph_vlan_interfaces'] = vlan_intfs
    results['minigraph_portchannel_interfaces'] = pc_intfs
    results['minigraph_mgmt_interface'] = mgmt_intf
    results['minigraph_lo_interfaces'] = lo_intfs
    results['minigraph_neighbors'] = neighbors
    results['minigraph_devices'] = devices
    results['minigraph_underlay_neighbors'] = u_neighbors
    results['minigraph_underlay_devices'] = u_devices
    # note - this may include files under acs/ansible/minigraph, or those under the default cache folder.
    # (see ANSIBLE_USER_MINIGRAPH_PATH at the top of the module)
    results['minigraph_as_xml'] = mini_graph_path
    results['minigraph_console'] = get_console_info(devices, console_dev, console_port)
    results['minigraph_mgmt'] = get_mgmt_info(devices, mgmt_dev, mgmt_port)

    return results


port_alias_map = {}

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
        os.mkdir(ANSIBLE_USER_MINIGRAPH_PATH)
    except OSError:
        if not os.path.isdir(ANSIBLE_USER_MINIGRAPH_PATH):
            # file conflict, report the error and exit.
            module.fail_json(msg="'{}' exists but is not a directory".format(ANSIBLE_USER_MINIGRAPH_PATH))

    m_args = module.params
    local_file_path = ANSIBLE_LOCAL_MINIGRAPH_PATH.format(m_args['host'])
    if 'filename' in m_args and m_args['filename'] is not None:
        # literal filename specified
        filename = "minigraph/%s" % m_args['filename']
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
        # all attempts to find a minigraph failed.
        module.fail_json(msg=e.message)


def print_parse_xml(hostname):
    filename = '../minigraph/' + hostname + '.xml'
    results = parse_xml(filename, hostname)
    print(json.dumps(results, indent=3, cls=minigraph_encoder))

from ansible.module_utils.basic import *

if __name__ == "__main__":
    main()
