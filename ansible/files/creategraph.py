#!/usr/bin/env python

import csv
import sys
import os
import argparse
from lxml import etree

try:
    from ansible.module_utils.port_utils import get_port_alias_to_name_map
except ImportError:
    # Add parent dir for using outside Ansible
    sys.path.append('..')
    from module_utils.port_utils import get_port_alias_to_name_map

DEFAULT_DEVICECSV = 'sonic_lab_devices.csv'
DEFAULT_LINKCSV = 'sonic_lab_links.csv'
DEFAULT_CONSOLECSV = 'sonic_lab_console_links.csv'
DEFAULT_PDUCSV = 'sonic_lab_pdu_links.csv'

LAB_CONNECTION_GRAPH_ROOT_NAME = 'LabConnectionGraph'
LAB_CONNECTION_GRAPH_DPGL2_NAME = 'DevicesL2Info'


class LabGraph(object):

    """
    This is used to create "graph" file of lab for all connections and vlan info from csv file
    We(both engineer and lab technician) maintian and modify the csv file to keep track of the lab
    infrastucture for Sonic development and testing environment.
    """

    def __init__(self, dev_csvfile=None, link_csvfile=None, cons_csvfile=None, pdu_csvfile=None, graph_xmlfile=None):
        self.devices = {}
        self.links = []
        self.consoles = []
        self.pdus = []
        self.devcsv = dev_csvfile
        self.linkcsv = link_csvfile
        self.conscsv = cons_csvfile
        self.pducsv = pdu_csvfile
        self.png_xmlfile = 'str_sonic_png.xml'
        self.dpg_xmlfile = 'str_sonic_dpg.xml'
        self.one_xmlfile = graph_xmlfile
        self._cache_port_name_to_alias = {}
        self._cache_port_alias_to_name = {}
        self.pngroot = etree.Element('PhysicalNetworkGraphDeclaration')
        self.dpgroot = etree.Element('DataPlaneGraph')
        self.csgroot = etree.Element('ConsoleGraphDeclaration')
        self.pcgroot = etree.Element('PowerControlGraphDeclaration')

    def _get_port_alias_to_name_map(self, hwsku):
        """
        Retrive port alias to name map for specific hwsku.
        """
        if hwsku in self._cache_port_alias_to_name:
            return self._cache_port_alias_to_name[hwsku]
        port_alias_to_name_map, _, _ = get_port_alias_to_name_map(hwsku)
        self._cache_port_alias_to_name[hwsku] = port_alias_to_name_map
        return port_alias_to_name_map

    def _get_port_name_to_alias_map(self, hwsku):
        """
        Retrive port name to alias map for specific hwsku.
        """
        if hwsku in self._cache_port_name_to_alias:
            return self._cache_port_name_to_alias[hwsku]
        port_alias_to_name_map = self._get_port_alias_to_name_map(hwsku)
        port_name_to_alias_map = dict([(name, alias) for alias, name in port_alias_to_name_map.items()])
        self._cache_port_name_to_alias[hwsku] = port_name_to_alias_map
        return port_name_to_alias_map

    def _get_port_name_set(self, device_hostname):
        """
        Retrive port name set of a specific hwsku.
        """
        hwsku = self.devices[device_hostname]['HwSku']
        return set(self._get_port_name_to_alias_map(hwsku).keys())

    def _get_port_alias_set(self, device_hostname):
        """
        Retrive port alias set of a specific hwsku.
        """
        hwsku = self.devices[device_hostname]['HwSku']
        return set(self._get_port_alias_to_name_map(hwsku).keys())

    def _convert_port_alias_to_name(self, device_hostname, port_alias):
        """
        Given the device hostname and port alias, return the corresponding port name.
        """
        devtype = self.devices[device_hostname]['Type'].lower()
        if 'sonic' not in devtype:
            raise Exception("Cannot convert port alias to name for non-SONiC device {}".format(device_hostname))
        hwsku = self.devices[device_hostname]['HwSku']
        port_alias_to_name_map = self._get_port_alias_to_name_map(hwsku)
        return port_alias_to_name_map[port_alias]

    def read_devices(self):
        with open(self.devcsv) as csv_dev:
            csv_devices = csv.DictReader(filter(lambda row: row[0] != '#' and len(row.strip()) != 0, csv_dev))
            devices_root = etree.SubElement(self.pngroot, 'Devices')
            pdus_root = etree.SubElement(self.pcgroot, 'DevicesPowerControlInfo')
            cons_root = etree.SubElement(self.csgroot, 'DevicesConsoleInfo')
            for row in csv_devices:
                attrs = {}
                self.devices[row['Hostname']] = row
                devtype = row['Type'].lower()
                if 'pdu' in devtype:
                    for key in row:
                        attrs[key] = row[key].decode('utf-8')
                    etree.SubElement(pdus_root, 'DevicePowerControlInfo', attrs)
                elif 'consoleserver' in devtype:
                    for key in row:
                        attrs[key] = row[key].decode('utf-8')
                    etree.SubElement(cons_root, 'DeviceConsoleInfo', attrs)
                else:
                    for key in row:
                        if key.lower() != 'managementip' and key.lower() != 'protocol':
                            attrs[key] = row[key].decode('utf-8')
                    etree.SubElement(devices_root, 'Device', attrs)

    def read_links(self):
        # Read and parse link.csv file
        with open(self.linkcsv) as csv_file:
            csv_links = csv.DictReader(filter(lambda row: row[0] != '#' and len(row.strip()) != 0, csv_file))
            links_group_by_devices = {}
            for link in csv_links:
                self.links.append(link)
                if link['StartDevice'] not in links_group_by_devices:
                    links_group_by_devices[link['StartDevice']] = []
                links_group_by_devices[link['StartDevice']].append(link)
                if link['EndDevice'] not in links_group_by_devices:
                    links_group_by_devices[link['EndDevice']] = []
                links_group_by_devices[link['EndDevice']].append(link)

        # For SONiC devices (DUT/Fanout), convert port alias to port name. Updates in `links_group_by_devices` will
        # also be reflected in `self.links`, because they are holding reference to the same underlying `link` variable.
        for device, links in links_group_by_devices.items():
            devtype = self.devices[device]['Type'].lower()
            if 'sonic' not in devtype:
                continue
            ports = []
            for link in links:
                if device == link['StartDevice']:
                    ports.append(link['StartPort'])
                elif device == link['EndDevice']:
                    ports.append(link['EndPort'])
            if any([port not in self._get_port_alias_set(device).union(self._get_port_name_set(device)) for port in ports]):
                # If any port of a device is neither port name nor port alias, skip conversion for this device.
                continue
            if all([port in self._get_port_alias_set(device) for port in ports]):
                # If all ports of a device are port alias, convert them to port name.
                for link in links:
                    if device == link['StartDevice']:
                        link['StartPort'] = self._convert_port_alias_to_name(device, link['StartPort'])
                    elif device == link['EndDevice']:
                        link['EndPort'] = self._convert_port_alias_to_name(device, link['EndPort'])
            elif not all([port in self._get_port_name_set(device) for port in ports]):
                # If some ports use port name and others use port alias, raise an Exception.
                raise Exception("[Failed] For device {}, please check {} and ensure all ports use port name, "
                                "or ensure all ports use port alias.".format(device, self.linkcsv))

        # Generate DeviceInterfaceLink XML nodes for connection graph
        links_root = etree.SubElement(self.pngroot, 'DeviceInterfaceLinks')
        for link in self.links:
            attrs = {}
            for key in link:
                if key.lower() != 'vlanid' and key.lower() != 'vlanmode':
                    attrs[key] = link[key].decode('utf-8')
            etree.SubElement(links_root, 'DeviceInterfaceLink', attrs)

    def read_consolelinks(self):
        if not os.path.exists(self.conscsv):
            return
        with open(self.conscsv) as csv_file:
            csv_cons = csv.DictReader(csv_file)
            conslinks_root = etree.SubElement(self.csgroot, 'ConsoleLinksInfo')
            for cons in csv_cons:
                attrs = {}
                for key in cons:
                    attrs[key] = cons[key].decode('utf-8')
                etree.SubElement(conslinks_root, 'ConsoleLinkInfo', attrs)
                self.consoles.append(cons)

    def read_pdulinks(self):
        if not os.path.exists(self.pducsv):
            return
        with open(self.pducsv) as csv_file:
            csv_pdus = csv.DictReader(csv_file)
            pduslinks_root = etree.SubElement(self.pcgroot, 'PowerControlLinksInfo')
            for pdu_link in csv_pdus:
                attrs = {}
                for key in pdu_link:
                    attrs[key] = pdu_link[key].decode('utf-8')
                etree.SubElement(pduslinks_root, 'PowerControlLinkInfo', attrs)
                self.pdus.append(pdu_link)

    def generate_dpg(self):
        for hostname in self.devices:
            managementip = self.devices[hostname].get('ManagementIp', '')
            devtype = self.devices[hostname]['Type'].lower()
            if not hostname:
                continue
            if devtype in ('server', 'devsonic'):
                # Build Management interface IP for server and DUT
                l3inforoot = etree.SubElement(self.dpgroot, 'DevicesL3Info', {'Hostname': hostname})
                etree.SubElement(l3inforoot, 'ManagementIPInterface', {'Name': 'ManagementIp', 'Prefix': managementip})
            elif 'fanout' in devtype or 'ixiachassis' in devtype:
                # Build Management interface IP here, if we create each device indivial minigraph file, we may comment this out
                l3inforoot = etree.SubElement(self.dpgroot, 'DevicesL3Info', {'Hostname': hostname})
                etree.SubElement(l3inforoot, 'ManagementIPInterface', {'Name': 'ManagementIp', 'Prefix': managementip})
                # Build L2 information Here
                l2inforoot = etree.SubElement(self.dpgroot, LAB_CONNECTION_GRAPH_DPGL2_NAME, {'Hostname': hostname})
                vlanattr = {}
                for link in self.links:
                    if link['StartDevice'] == hostname:
                        vlanattr['portname'] = link['StartPort']
                    if link['EndDevice'] == hostname:
                        vlanattr['portname'] = link['EndPort']
                    if link['StartDevice'] == hostname or link['EndDevice'] == hostname:
                        vlanattr['vlanids'] = link['VlanID']
                        vlanattr['mode'] = link['VlanMode']
                        etree.SubElement(l2inforoot, 'InterfaceVlan', vlanattr)

    def create_xml(self):
        '''

        if two seperate file of png and dpg needed, uncomment these part

        pngxml = open(self.png_xmlfile, 'w')
        png = etree.tostring(self.pngroot, pretty_print=True)
        pngxml.write(png)

        pngxml = open(self.dpg_xmlfile, 'w')
        dpg = etree.tostring(self.dpgroot, pretty_print=True)
        pngxml.write(dpg)
        '''

        onexml = open(self.one_xmlfile, 'w')
        root = etree.Element(LAB_CONNECTION_GRAPH_ROOT_NAME)
        root.append(self.pngroot)
        root.append(self.dpgroot)
        root.append(self.csgroot)
        root.append(self.pcgroot)
        result = etree.tostring(root, pretty_print=True)
        onexml.write(result)


def get_file_names(args):
    if not args.inventory:
        device, links, console, pdu = args.device, args.links, args.console, args.pdu
    else:
        device = 'sonic_{}_devices.csv'.format(args.inventory)
        links = 'sonic_{}_links.csv'.format(args.inventory)
        console = 'sonic_{}_console_links.csv'.format(args.inventory)
        pdu = 'sonic_{}_pdu_links.csv'.format(args.inventory)

    return device, links, console, pdu


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--device", help="device file [deprecate warning: use -i instead]", default=DEFAULT_DEVICECSV)
    parser.add_argument("-l", "--links", help="link file [deprecate warning: use -i instead]", default=DEFAULT_LINKCSV)
    parser.add_argument("-c", "--console", help="console connection file [deprecate warning: use -i instead]", default=DEFAULT_CONSOLECSV)
    parser.add_argument("-p", "--pdu", help="pdu connection file [deprecate warning: use -i instead]", default=DEFAULT_PDUCSV)
    parser.add_argument("-i", "--inventory", help="specify inventory namei to generate device/link/console/pdu file names, default none", default=None)
    parser.add_argument("-o", "--output", help="output xml file", required=True)
    args = parser.parse_args()

    device, links, console, pdu = get_file_names(args)
    mygraph = LabGraph(device, links, console, pdu, args.output)

    mygraph.read_devices()
    mygraph.read_links()
    mygraph.read_consolelinks()
    mygraph.read_pdulinks()
    mygraph.generate_dpg()
    mygraph.create_xml()


if __name__ == '__main__':
    main()
