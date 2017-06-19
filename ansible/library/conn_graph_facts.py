#!/usr/bin/env python

import lxml.etree as ET
import yaml
import os
import traceback
import ipaddr as ipaddress
from operator import itemgetter
from itertools import groupby
from collections import defaultdict

DOCUMENTATION='''
module: conn_graph_facts.py
version_added:  2.0
short_description: Retrive lab fanout switches physical and vlan connections 
Description:
    Retrive lab fanout switches physical and vlan connections
    add to Ansible facts
options:
    host:  [fanout switch name|Server name|Sonic Switch Name]
    requred: True

Ansible_facts:
    device_info: The device(host) type and hwsku
    device_conn: each physical connection of the device(host)
    device_vlan_range: all configured vlan range for the device(host) 
    device_port_vlans: detailed vlanids for each physical port and switchport mode
    server_links: each server port vlan ids

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

LAB_CONNECTION_GRAPH_FILE = 'lab_connection_graph.xml'
LAB_GRAPHFILE_PATH = 'files/'

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
        self.server = defaultdict(dict)
        self.pngtag = 'PhysicalNetworkGraphDeclaration'
        self.dpgtag = 'DataPlaneGraph'

    def port_vlanlist(self, vlanrange):
        vlans = []
        for vlanid in list(map(str.strip,vlanrange.split(','))):
            if vlanid.isdigit():
                vlans.append(int(vlanid))
                continue
            elif '-' in vlanid:
                vlanlist = list(map(str.strip,vlanid.split('-')))
                vlans.extend(range(int(vlanlist[0]), int(vlanlist[1])+1))
                continue
            elif vlanid != '':
                raise Exception, 'vlan range error "%s"'%vlanrange
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
                    self.links[start_dev][link.attrib['StartPort']] = {'peerdevice':link.attrib['EndDevice'], 'peerport': link.attrib['EndPort']}
                if end_dev:
                    self.links[end_dev][link.attrib['EndPort']] = {'peerdevice': link.attrib['StartDevice'], 'peerport': link.attrib['StartPort']}
        self.devices = deviceinfo
        self.vlanport = devicel2info

    def convert_list2range(self, l):
        """
        common module to convert a  list to range for easier vlan configuration generation
        """
        ranges = []
        sl = sorted(set(l))
        for k,g in groupby(enumerate(sl), lambda (i,x): i-x):
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

        if hostname in self.devices and  self.devices[hostname]['Type'].lower() == 'devsonic':
            self.vlanport[hostname] = {}
            for port in self.links[hostname]:
                peerdevice = self.links[hostname][port]['peerdevice']
                peerport = self.links[hostname][port]['peerport']
                peerportmode = self.vlanport[peerdevice][peerport]['mode']
                peervlanids = self.vlanport[peerdevice][peerport]['vlanids']
                peervlanlist = self.vlanport[peerdevice][peerport]['vlanlist']
                self.vlanport[hostname][port] = {'mode': peerportmode, 'vlanids': peervlanids, 'vlanlist': peervlanlist}

        if hostname in self.vlanport:
            dpgvlans = self.vlanport[hostname]
            vlans  = []
            for intf in dpgvlans:
                vlans += dpgvlans[intf]['vlanlist']
            self.vlanrange = self.convert_list2range(vlans)
            return {'VlanRange': self.vlanrange, 'VlanList': vlans }

    def get_host_device_info(self, hostname):
        """
        return  the given hostname device info of hwsku and type
        """
        if hostname in self.devices:
            return  self.devices[hostname]
        else:
            return self.devices

    def get_host_port_vlans(self, hostname):
        """
        return the given hostname device  vlan port information
        """
        if hostname in self.vlanport:
            return self.vlanport[hostname]
        else:
            return self.vlanport

    def get_host_connections(self, hostname):
        """
        return the given hostname device each individual connection
        """
        if hostname in self.links:
            return self.links[hostname]
        else:
            return self.links

def main():
    module = AnsibleModule(
        argument_spec=dict(
            host=dict(required=False),
            filename=dict(required=False),
        ),
        supports_check_mode=True
    )
    m_args = module.params
    hostname = m_args['host']
    try:
        lab_graph = Parse_Lab_Graph(LAB_GRAPHFILE_PATH+LAB_CONNECTION_GRAPH_FILE)
        lab_graph.parse_graph()
        dev = lab_graph.get_host_device_info(hostname)
        if dev is None:
            module.fail_json(msg="cannot find info for "+hostname)
        results = {}
        results['device_info'] =  lab_graph.get_host_device_info(hostname)
        results['device_conn'] = lab_graph.get_host_connections(hostname)
        if lab_graph.get_host_vlan(hostname):
            results['device_vlan_range'] = lab_graph.get_host_vlan(hostname)['VlanRange']
            results['device_vlan_list'] = lab_graph.get_host_vlan(hostname)['VlanList']
        results['device_port_vlans'] = lab_graph.get_host_port_vlans(hostname)
        module.exit_json(ansible_facts=results)
    except (IOError, OSError):
        module.fail_json(msg="Can not find lab graph file "+LAB_CONNECTION_GRAPH_FILE)
    except Exception as e:
        module.fail_json(msg=traceback.format_exc())


from ansible.module_utils.basic import *
if __name__== "__main__":
    main()


