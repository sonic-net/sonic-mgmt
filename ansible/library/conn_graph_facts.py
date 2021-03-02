#!/usr/bin/env python

import lxml.etree as ET
import yaml
import os
import traceback
import ipaddr as ipaddress
from operator import itemgetter
from itertools import groupby
from collections import defaultdict
from natsort import natsorted

try:
    from ansible.module_utils.port_utils import get_port_alias_to_name_map
    from ansible.module_utils.debug_utils import create_debug_file, print_debug_msg
except ImportError:
    # Add parent dir for using outside Ansible
    import sys
    sys.path.append('..')
    from module_utils.port_utils import get_port_alias_to_name_map
    from module_utils.debug_utils import create_debug_file, print_debug_msg

DOCUMENTATION='''
module: conn_graph_facts.py
version_added:  2.0
short_description: Retrive lab fanout switches physical and vlan connections
Description:
    Retrive lab fanout switches physical and vlan connections
    add to Ansible facts
options:
    host:
        [fanout switch name|Server name|Sonic Switch Name]
        required: False
    hosts:
        List of hosts. Applicable for multi-DUT and single-DUT setup. The host option for single DUT setup is kept
        for backward compatibility.
        required: False
    anchor:
        List of hosts. When no host and hosts is provided, the anchor option must be specified with list of hosts.
        This option is to supply the relevant list of hosts for looking up the connection graph xml file which has
        all the supplied hosts. The whole graph will be returned when this option is used. This is for configuring
        the root fanout switch.
        required: False
    filepath:
        Path of the connection graph xml file. Override the default path for looking up connection graph xml file.
        required: False
    filename:
        Name of the connection graph xml file. Override the behavior of looking up connection graph xml file. When
        this option is specified, always use the specified connection graph xml file.
        required: False

    Mutually exclusive options: host, hosts, anchor

Ansible_facts:
    device_info: The device(host) type and hwsku
    device_conn: each physical connection of the device(host)
    device_vlan_range: all configured vlan range for the device(host)
    device_port_vlans: detailed vlanids for each physical port and switchport mode
    server_links: each server port vlan ids
    device_console_info: The device's console server type, mgmtip, hwsku and protocol
    device_console_link:  The console server port connected to the device
    device_pdu_info: The device's pdu server type, mgmtip, hwsku and protocol
    device_pdu_links: The pdu server ports connected to the device

'''


EXAMPLES='''
    - name: conn_graph_facts: host = "str-7260-11"

    return:
          "device_info": {
              "ManagementIp": "10.251.0.76/24",
              "HwSku": "Arista-7260QX-64",
              "Type": "FanoutLeaf"
            },
          "device_conn": [
          {
             "StartPort": "Ethernet0",
             "EndPort": "Ethernet33",
             "StartDevice": "str-s6000-on-1",
             "VlanID": "233",
             "BandWidth": "40000",
             "VlanMode": "Access",
             "EndDevice": "str-7260-01"
           },
           {...}
           ],
           "device_vlan_range": {
              "VlanRange": "201-980,1041-1100"
            },
           "device_vlan_port:=: {
                ...
              "Ethernet44": {
                "vlanids": "801-860",
                "mode": "Trunk"
              },
              "Ethernet42": {
                "vlanids": "861-920",
                "mode": "Trunk"
               },......
            }


'''


debug_fname = None


class Parse_Lab_Graph():
    """
    Parse the generated lab physical connection graph and insert Ansible fact of the graph
    for deploying fanout switches and dynamically configure vlan mapping to hook up EOS VMs
    and ptf docker for lab testing

    There is a creategraph.py under ansible/files to create the png and dpg like graph file for lab devices from csv file
    The  2 csv files under ansible/files are csv files to list all devices and device links for Sonic testbed
    There is a sonic_server_links.yml file to describe the connections between servers port and Sonic devices
    This module conn_graph_file also parse the server links to have a full root fanout switches template for deployment.
    """

    def __init__(self, xmlfile):
        self.root = ET.parse(xmlfile)
        self.devices = {}
        self.vlanport = {}
        self.vlanrange = {}
        self.links = {}
        self.consolelinks = {}
        self.pdulinks = {}
        self.server = defaultdict(dict)
        self.pngtag = 'PhysicalNetworkGraphDeclaration'
        self.dpgtag = 'DataPlaneGraph'
        self.pcgtag = 'PowerControlGraphDeclaration'
        self.csgtag = 'ConsoleGraphDeclaration'

    def port_vlanlist(self, vlanrange):
        vlans = []
        for vlanid in list(map(str.strip, vlanrange.split(','))):
            if vlanid.isdigit():
                vlans.append(int(vlanid))
                continue
            elif '-' in vlanid:
                vlanlist = list(map(str.strip, vlanid.split('-')))
                vlans.extend(range(int(vlanlist[0]), int(vlanlist[1])+1))
                continue
            elif vlanid != '':
                raise ValueError('vlan range error "%s"' % vlanrange)
        vlans = sorted(set(vlans))
        return vlans

    def parse_graph(self):
        """
        Parse  the xml graph file
        """
        deviceinfo = {}
        deviceroot = self.root.find(self.pngtag).find('Devices')
        devices = deviceroot.findall('Device')
        if devices is not None:
            for dev in devices:
                hostname = dev.attrib['Hostname']
                if hostname is not None:
                    deviceinfo[hostname] = {}
                    hwsku = dev.attrib['HwSku']
                    devtype = dev.attrib['Type']
                    deviceinfo[hostname]['HwSku'] = hwsku
                    deviceinfo[hostname]['Type'] = devtype
                    self.links[hostname] = {}
        devicel2info = {}
        devicel3s = self.root.find(self.dpgtag).findall('DevicesL3Info')
        devicel2s = self.root.find(self.dpgtag).findall('DevicesL2Info')
        if devicel2s is not None:
            for l2info in devicel2s:
                hostname = l2info.attrib['Hostname']
                if hostname is not None:
                    devicel2info[hostname] = {}
                    vlans = l2info.findall('InterfaceVlan')
                    for vlan in vlans:
                        portname = vlan.attrib['portname']
                        portmode = vlan.attrib['mode']
                        portvlanid = vlan.attrib['vlanids']
                        portvlanlist = self.port_vlanlist(portvlanid)
                        devicel2info[hostname][portname] = {'mode': portmode, 'vlanids': portvlanid, 'vlanlist': portvlanlist}
        if devicel3s is not None:
            for l3info in devicel3s:
                hostname = l3info.attrib['Hostname']
                if hostname is not None:
                    management_ip = l3info.find('ManagementIPInterface').attrib['Prefix']
                    deviceinfo[hostname]['ManagementIp'] = management_ip
                    mgmtip = ipaddress.IPNetwork(management_ip)
                    deviceinfo[hostname]['mgmtip'] = str(mgmtip.ip)
                    management_gw = str(mgmtip.network+1)
                    deviceinfo[hostname]['ManagementGw'] = management_gw
        allinks = self.root.find(self.pngtag).find('DeviceInterfaceLinks').findall('DeviceInterfaceLink')
        if allinks is not None:
            for link in allinks:
                start_dev = link.attrib['StartDevice']
                end_dev = link.attrib['EndDevice']
                if start_dev:
                    self.links[start_dev][link.attrib['StartPort']] = {'peerdevice':link.attrib['EndDevice'], 'peerport': link.attrib['EndPort'], 'speed': link.attrib['BandWidth']}
                if end_dev:
                    self.links[end_dev][link.attrib['EndPort']] = {'peerdevice': link.attrib['StartDevice'], 'peerport': link.attrib['StartPort'], 'speed': link.attrib['BandWidth']}
        console_root = self.root.find(self.csgtag)
        if console_root:
            devicecsgroot = console_root.find('DevicesConsoleInfo')
            devicescsg = devicecsgroot.findall('DeviceConsoleInfo')
            if devicescsg is not None:
                for dev in devicescsg:
                    hostname = dev.attrib['Hostname']
                    if hostname is not None:
                        deviceinfo[hostname] = {}
                        hwsku = dev.attrib['HwSku']
                        devtype = dev.attrib['Type']
                        protocol = dev.attrib['Protocol']
                        mgmt_ip = dev.attrib['ManagementIp']
                        deviceinfo[hostname]['HwSku'] = hwsku
                        deviceinfo[hostname]['Type'] = devtype
                        deviceinfo[hostname]['Protocol'] = protocol
                        deviceinfo[hostname]['ManagementIp'] = mgmt_ip
                        self.consolelinks[hostname] = {}
            console_link_root = console_root.find('ConsoleLinksInfo')
            if console_link_root:
                allconsolelinks = console_link_root.findall('ConsoleLinkInfo')
                if allconsolelinks is not None:
                    for consolelink in allconsolelinks:
                        start_dev = consolelink.attrib['StartDevice']
                        end_dev = consolelink.attrib['EndDevice']
                        if start_dev:
                            if start_dev not in self.consolelinks:
                                self.consolelinks.update({start_dev : {}})
                            self.consolelinks[start_dev][consolelink.attrib['StartPort']] = {'peerdevice':consolelink.attrib['EndDevice'], 'peerport': 'ConsolePort'}
                        if end_dev:
                            if end_dev not in self.consolelinks:
                                self.consolelinks.update({end_dev : {}})
                            self.consolelinks[end_dev]['ConsolePort'] = {'peerdevice': consolelink.attrib['StartDevice'], 'peerport': consolelink.attrib['StartPort']}

        pdu_root = self.root.find(self.pcgtag)
        if pdu_root:
            devicepcgroot = pdu_root.find('DevicesPowerControlInfo')
            devicespcsg = devicepcgroot.findall('DevicePowerControlInfo')
            if devicespcsg is not None:
                for dev in devicespcsg:
                    hostname = dev.attrib['Hostname']
                    if hostname is not None:
                        deviceinfo[hostname] = {}
                        hwsku = dev.attrib['HwSku']
                        devtype = dev.attrib['Type']
                        protocol = dev.attrib['Protocol']
                        mgmt_ip = dev.attrib['ManagementIp']
                        deviceinfo[hostname]['HwSku'] = hwsku
                        deviceinfo[hostname]['Type'] = devtype
                        deviceinfo[hostname]['Protocol'] = protocol
                        deviceinfo[hostname]['ManagementIp'] = mgmt_ip
                        self.pdulinks[hostname] = {}
            pdu_link_root = pdu_root.find('PowerControlLinksInfo')
            if pdu_link_root:
                allpdulinks = pdu_link_root.findall('PowerControlLinkInfo')
                if allpdulinks is not None:
                    for pdulink in allpdulinks:
                        start_dev = pdulink.attrib['StartDevice']
                        end_dev = pdulink.attrib['EndDevice']
                        print_debug_msg(debug_fname, "pdulink {}".format(pdulink.attrib))
                        print_debug_msg(debug_fname, "self.pdulinks {}".format(self.pdulinks))
                        if start_dev:
                            if start_dev not in self.pdulinks:
                                self.pdulinks.update({start_dev : {}})
                            self.pdulinks[start_dev][pdulink.attrib['StartPort']] = {'peerdevice':pdulink.attrib['EndDevice'], 'peerport': pdulink.attrib['EndPort']}
                        if end_dev:
                            if end_dev not in self.pdulinks:
                                self.pdulinks.update({end_dev : {}})
                            self.pdulinks[end_dev][pdulink.attrib['EndPort']] = {'peerdevice': pdulink.attrib['StartDevice'], 'peerport': pdulink.attrib['StartPort']}
        self.devices = deviceinfo
        self.vlanport = devicel2info

    def convert_list2range(self, l):
        """
        common module to convert a  list to range for easier vlan configuration generation
        """
        ranges = []
        sl = sorted(set(l))
        for _, g in groupby(enumerate(sl), lambda t: t[0] - t[1]):
            group = list(map(itemgetter(1), g))
            if len(group) == 1:
                ranges.append(str(group[0]))
            else:
                ranges.append(str(group[0])+'-'+str(group[-1]))
        return ranges

    def get_server_links(self):
        return self.server

    def get_host_vlan(self, hostname):
        """
        Calculate dpg vlan data for each link(port) and return a Switch/Device total Vlan range
        """

        if hostname in self.devices and self.devices[hostname]['Type'].lower() == 'devsonic':
            self.vlanport[hostname] = {}
            for port in self.links[hostname]:
                peerdevice = self.links[hostname][port]['peerdevice']
                if self.devices[peerdevice]["Type"].lower() == "devsonic":
                    continue
                peerport = self.links[hostname][port]['peerport']
                peerportmode = self.vlanport[peerdevice][peerport]['mode']
                peervlanids = self.vlanport[peerdevice][peerport]['vlanids']
                peervlanlist = self.vlanport[peerdevice][peerport]['vlanlist']
                self.vlanport[hostname][port] = {'mode': peerportmode, 'vlanids': peervlanids, 'vlanlist': peervlanlist}

        if hostname in self.vlanport:
            dpgvlans = self.vlanport[hostname]
            vlans = []
            for intf in dpgvlans:
                vlans += dpgvlans[intf]['vlanlist']
            self.vlanrange = self.convert_list2range(vlans)
            return {'VlanRange': self.vlanrange, 'VlanList': vlans}

    def get_host_device_info(self, hostname):
        """
        return  the given hostname device info of hwsku and type
        """
        return self.devices.get(hostname)

    def get_host_port_vlans(self, hostname):
        """
        return the given hostname device  vlan port information
        """
        return self.vlanport.get(hostname)

    def get_host_connections(self, hostname):
        """
        return the given hostname device each individual connection
        """
        return self.links.get(hostname)

    def contains_hosts(self, hostnames, part):
        if not part:
            return set(hostnames) <= set(self.devices)
        # It's possible that not all devices are found in connect_graph when using in devutil
        THRESHOLD = 0.8
        count = 0
        for hostname in hostnames:
            if hostname in self.devices.keys():
                count += 1
        return hostnames and (count * 1.0 / len(hostnames) >= THRESHOLD)


    def get_host_console_info(self, hostname):
        """
        return  the given hostname console info of mgmtip, protocol, hwsku and type
        """
        if hostname in self.devices:
            try:
                ret = self.devices[self.consolelinks[hostname]['ConsolePort']['peerdevice']]
            except KeyError:
                ret = {}
            return ret
        else:
            """
            Please be noted that an empty dict is returned when hostname is not found
            The behavior is different with get_host_vlan. devutils script will check if the returned dict
            is empty to determine if console info exists for given hostname.
            """
            return {}

    def get_host_console_link(self, hostname):
        """
        return  the given hostname console link info of console server and port
        """
        if hostname in self.consolelinks:
            return  self.consolelinks[hostname]
        else:
            # Please be noted that an empty dict is returned when hostname is not found
            return {}

    def get_host_pdu_info(self, hostname):
        """
        return  the given hostname pdu info of mgmtip, protocol, hwsku and type
        """
        if hostname in self.devices:
            ret = {}
            for key in ['PSU1', 'PSU2']:
                try:
                    ret.update({key : self.devices[self.pdulinks[hostname][key]['peerdevice']]})
                except KeyError:
                    pass
            return ret
        else:
            # Please be noted that an empty dict is returned when hostname is not found
            return {}

    def get_host_pdu_links(self, hostname):
        """
        return  the given hostname pdu links info of pdu servers and ports
        """
        if hostname in self.pdulinks:
            return  self.pdulinks[hostname]
        else:
            # Please be noted that an empty dict is returned when hostname is not found
            return {}


LAB_CONNECTION_GRAPH_FILE = 'graph_files.yml'
EMPTY_GRAPH_FILE = 'empty_graph.xml'
LAB_GRAPHFILE_PATH = 'files/'


def find_graph(hostnames, part=False):
    """
    Find a graph file contains all devices in testbed.
    duts are spcified by hostnames

    Parameters:
        hostnames: list of duts in the target testbed.
        part: select the graph file if over 80% of hosts are found in conn_graph when part is True
    """
    global debug_fname
    filename = os.path.join(LAB_GRAPHFILE_PATH, LAB_CONNECTION_GRAPH_FILE)
    with open(filename) as fd:
        file_list = yaml.safe_load(fd)

    # Finding the graph file contains all duts from hostnames,
    for fn in file_list:
        print_debug_msg(debug_fname, "Looking at conn graph file: %s for hosts %s" % (fn, hostnames))
        filename = os.path.join(LAB_GRAPHFILE_PATH, fn)
        lab_graph = Parse_Lab_Graph(filename)
        lab_graph.parse_graph()
        print_debug_msg(debug_fname, "For file %s, got hostnames %s" % (fn, lab_graph.devices))
        if lab_graph.contains_hosts(hostnames, part):
            print_debug_msg(debug_fname, ("Returning lab graph from conn graph file: %s for hosts %s" % (fn, hostnames)))
            return lab_graph
    # Fallback to return an empty connection graph, this is
    # needed to bridge the kvm test needs. The KVM test needs
    # A graph file, which used to be whatever hardcoded file.
    # Here we provide one empty file for the purpose.
    lab_graph = Parse_Lab_Graph(os.path.join(LAB_GRAPHFILE_PATH, EMPTY_GRAPH_FILE))
    lab_graph.parse_graph()
    return lab_graph


def get_port_name_list(hwsku):
    # Create a map of SONiC port name to physical port index
    # Start by creating a list of all port names
    port_alias_to_name_map = get_port_alias_to_name_map(hwsku)

    # Create a map of SONiC port name to physical port index
    # Start by creating a list of all port names
    port_name_list = port_alias_to_name_map.values()
    # Sort the list in natural order, because SONiC port names, when
    # sorted in natural sort order, match the phyical port index order
    port_name_list_sorted = natsorted(port_name_list)
    return port_name_list_sorted

def build_results(lab_graph, hostnames, ignore_error=False):
    """
    Refactor code for building json results.
    Code is refactored because same logic is needed in devutil
    """
    device_info = {}
    device_conn = {}
    device_port_vlans = {}
    device_vlan_range = {}
    device_vlan_list = {}
    device_vlan_map_list = {}
    device_console_info = {}
    device_console_link = {}
    device_pdu_info = {}
    device_pdu_links = {}
    msg = {}
    for hostname in hostnames:
        dev = lab_graph.get_host_device_info(hostname)
        if dev is None and not ignore_error:
            msg = "cannot find info for %s" % hostname
            return (False, msg)
        device_info[hostname] = dev
        device_conn[hostname] = lab_graph.get_host_connections(hostname)
        host_vlan = lab_graph.get_host_vlan(hostname)
        port_vlans = lab_graph.get_host_port_vlans(hostname)
        # for multi-DUTs, must ensure all have vlan configured.
        if host_vlan:
            device_vlan_range[hostname] = host_vlan["VlanRange"]
            device_vlan_list[hostname] = host_vlan["VlanList"]
            if dev["Type"].lower() != "devsonic":
                device_vlan_map_list[hostname] = host_vlan["VlanList"]
            else:
                device_vlan_map_list[hostname] = {}

                port_name_list_sorted = get_port_name_list(dev['HwSku'])
                print_debug_msg(debug_fname, "For %s with hwsku %s, port_name_list is %s" % (hostname, dev['HwSku'], port_name_list_sorted))
                for a_host_vlan in host_vlan["VlanList"]:
                    # Get the corresponding port for this vlan from the port vlan list for this hostname
                    found_port_for_vlan = False
                    for a_port in port_vlans:
                        if a_host_vlan in port_vlans[a_port]['vlanlist']:
                            if a_port in port_name_list_sorted:
                                port_index = port_name_list_sorted.index(a_port)
                                device_vlan_map_list[hostname][port_index] = a_host_vlan
                                found_port_for_vlan = True
                                break
                            elif not ignore_error:
                                msg = "Did not find port for %s in the ports based on hwsku '%s' for host %s" % (a_port, dev['HwSku'], hostname)
                                return (False, msg)
                    if not found_port_for_vlan and not ignore_error:
                        msg = "Did not find corresponding link for vlan %d in %s for host %s" % (a_host_vlan, port_vlans, hostname)
                        return (False, msg)
        device_port_vlans[hostname] = port_vlans
        device_console_info[hostname] = lab_graph.get_host_console_info(hostname)
        device_console_link[hostname] = lab_graph.get_host_console_link(hostname)
        device_pdu_info[hostname] = lab_graph.get_host_pdu_info(hostname)
        device_pdu_links[hostname] = lab_graph.get_host_pdu_links(hostname)
    results = {k: v for k, v in locals().items()
                   if (k.startswith("device_") and v)}
    return (True, results)

def main():
    module = AnsibleModule(
        argument_spec=dict(
            host=dict(required=False),
            hosts=dict(required=False, type='list'),
            filename=dict(required=False),
            filepath=dict(required=False),
            anchor=dict(required=False, type='list'),
        ),
        mutually_exclusive=[['host', 'hosts', 'anchor']],
        supports_check_mode=True
    )
    m_args = module.params
    global debug_fname
    debug_fname = create_debug_file("/tmp/conn_graph_debug.txt")

    anchor = m_args['anchor']
    if m_args['hosts']:
        hostnames = m_args['hosts']
    elif m_args['host']:
        hostnames = [m_args['host']]
    else:
        # return the whole graph
        hostnames = []
    try:
        # When called by pytest, the file path is obscured to /tmp/.../.
        # we need the caller to tell us where the graph files are with
        # filepath argument.
        if m_args['filepath']:
            global LAB_GRAPHFILE_PATH
            LAB_GRAPHFILE_PATH = m_args['filepath']

        if m_args['filename']:
            filename = os.path.join(LAB_GRAPHFILE_PATH, m_args['filename'])
            lab_graph = Parse_Lab_Graph(filename)
            lab_graph.parse_graph()
        else:
            # When calling passed in anchor instead of hostnames,
            # the caller is asking to return the whole graph. This
            # is needed when configuring the root fanout switch.
            target = anchor if anchor else hostnames
            lab_graph = find_graph(target)

        # early return for the whole graph or empty graph file(vtestbed)
        if (
                not hostnames or
                not lab_graph.devices and not lab_graph.links and not lab_graph.vlanport
        ):
            results = {
                'device_info': lab_graph.devices,
                'device_conn': lab_graph.links,
                'device_port_vlans': lab_graph.vlanport,
            }
            module.exit_json(ansible_facts=results)
        succeed, results = build_results(lab_graph, hostnames)
        if succeed:
            module.exit_json(ansible_facts=results)
        else:
            module.fail_json(msg=results)
    except (IOError, OSError):
        module.fail_json(msg="Can not find lab graph file under {}".format(LAB_GRAPHFILE_PATH))
    except Exception as e:
        module.fail_json(msg=traceback.format_exc())


from ansible.module_utils.basic import *
if __name__ == "__main__":
    main()
