#!/usr/bin/env python

import csv
import sys
import os, re, json
import argparse
from lxml import etree
from collections import OrderedDict
try:
    from ansible.module_utils.port_utils import get_port_alias_to_name_map
except ImportError:
    # Add parent dir for using outside Ansible
    import sys
    sys.path.append('..')
    from module_utils.port_utils import get_port_alias_to_name_map

ALLOWED_HEADER = ['name', 'lanes', 'alias', 'index', 'asic_port_name', 'role', 'speed']
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

    def __init__(self, dev_csvfile=None, link_csvfile=None, cons_csvfile=None, pdu_csvfile=None, graph_xmlfile=None, names=None):
        #TODO:make generated xml file name as parameters in the future to make it more flexible
        self.names = []
        self.devices = []
        self.links =  []
        self.consoles =  []
        self.pdus =  []
        self.devcsv = dev_csvfile
        self.linkcsv = link_csvfile
        self.conscsv = cons_csvfile
        self.pducsv = pdu_csvfile
        self.names = names
        self.png_xmlfile = 'str_sonic_png.xml'
        self.dpg_xmlfile = 'str_sonic_dpg.xml'
        self.one_xmlfile = graph_xmlfile
        self.pngroot = etree.Element('PhysicalNetworkGraphDeclaration')
        self.dpgroot = etree.Element('DataPlaneGraph')
        self.csgroot = etree.Element('ConsoleGraphDeclaration')
        self.pcgroot = etree.Element('PowerControlGraphDeclaration')

    def read_devices(self):
        with open(self.devcsv) as csv_dev:
            csv_devices = csv.DictReader(filter(lambda row: row[0]!='#' and len(row.strip())!=0, csv_dev))
            devices_root = etree.SubElement(self.pngroot, 'Devices')
            pdus_root = etree.SubElement(self.pcgroot, 'DevicesPowerControlInfo')
            cons_root = etree.SubElement(self.csgroot, 'DevicesConsoleInfo')
            for row in csv_devices:
                attrs = {}
                self.devices.append(row)
                devtype=row['Type'].lower()
                if 'pdu' in devtype:
                    for  key in row:
                        attrs[key]=row[key].decode('utf-8')
                    etree.SubElement(pdus_root, 'DevicePowerControlInfo', attrs)
                elif 'consoleserver' in devtype:
                    for  key in row:
                        attrs[key]=row[key].decode('utf-8')
                    etree.SubElement(cons_root, 'DeviceConsoleInfo', attrs)
                else:
                    for  key in row:
                        if key.lower() != 'managementip' and key.lower() !='protocol':
                            attrs[key]=row[key].decode('utf-8')
                    etree.SubElement(devices_root, 'Device', attrs)
 
    def read_links(self):
        with open(self.linkcsv) as csv_file:
            csv_links = csv.DictReader(filter(lambda row: row[0]!='#' and len(row.strip())!=0, csv_file))
            links_root = etree.SubElement(self.pngroot, 'DeviceInterfaceLinks')
            i = 0
            for link in csv_links:
                attrs = {}
                for key in link:
                    if key.lower() != 'vlanid' and key.lower() != 'vlanmode':
                        attrs[key]=link[key].decode('utf-8')
                    if key.lower() == 'startport' and link['StartDevice'] == 'sonicdut':
                        attrs[key]='Ethernet'+str(self.names[i])
                        i = i + 1
                print(attrs)
                etree.SubElement(links_root, 'DeviceInterfaceLink', attrs)
                self.links.append(link)
 
    def read_consolelinks(self):
        if not os.path.exists(self.conscsv):
            return
        with open(self.conscsv) as csv_file:
            csv_cons = csv.DictReader(csv_file)
            conslinks_root = etree.SubElement(self.csgroot, 'ConsoleLinksInfo')
            for cons in csv_cons:
                attrs = {}
                for key in cons:
                    attrs[key]=cons[key].decode('utf-8')
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
                    attrs[key]=pdu_link[key].decode('utf-8')
                etree.SubElement(pduslinks_root, 'PowerControlLinkInfo', attrs)
                self.pdus.append(pdu_link)

    def generate_dpg(self):
        for dev in self.devices:
            hostname = dev.get('Hostname', '')
            managementip = dev.get('ManagementIp', '')
            devtype = dev['Type'].lower()
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

def get_portmap(filename="./port_config.ini"):
    port_alias_to_name_map = {}
    objects = []
    names = []
    with open(filename) as f:
        lines = f.readlines()
    print(len(lines))
    alias_index = -1
    lanes_index = -1
    speed_index = -1
    role_index = -1
    asic_name_index = -1
    index_index = -1
    counter = 0
    while len(lines) != 0:
        line = lines.pop(0)
        counter = counter + 1
        if counter > 33:
            break
        if re.match('^#', line):
            title=re.sub('#', '', line.strip().lower()).split()
            for text in title:
                if text in ALLOWED_HEADER:
                    index = title.index(text)
                    if 'index' in text:
                        index_index = index
                    if 'alias' in text:
                        alias_index = index
                    if 'lanes' in text:
                        lanes_index = index
                    if 'speed' in text:
                        speed_index = index
                    if 'role' in text:
                        role_index = index
                    if 'asic_port_name' in text:
                        asic_name_index = index
        else:
            single_objects = {}
            #added support to parse recycle port
            if re.match('^Ethernet', line) or re.match('^Inband', line):
                mapping = line.split()
                name = mapping[0]
                names.append(name)
                single_objects["name"] = name
                if (lanes_index != -1) and (len(mapping) > lanes_index):
                    lanes = mapping[lanes_index]
                    single_objects["lanes"] = lanes
                else:
                    lanes = ''
                    single_objects["lanes"] = lanes
                if (index_index != -1) and (len(mapping) > index_index):
                    single_objects["index"] = mapping[index_index]
            
                if (role_index != -1) and (len(mapping) > role_index):
                    role = mapping[role_index]
                    single_objects["role"] = role
                else:
                    role = 'Ext'
                    single_objects["role"] = role
                if alias_index != -1 and len(mapping) > alias_index:
                    alias = mapping[alias_index]
                    single_objects["alias"] = alias
                else:
                    alias = name
                    single_objects["alias"] = alias
                port_alias_to_name_map[alias] = name
                if role == 'Ext':
                    if (speed_index != -1) and (len(mapping) > speed_index):
                        single_objects["speed"] = mapping[speed_index]
                    if (asic_name_index != -1) and (len(mapping) > asic_name_index):
                        asicifname = mapping[asic_name_index]
                        single_objects["asic_port_name"] = mapping[asic_name_index]
                if (asic_name_index != -1) and (len(mapping) > asic_name_index):
                    asicifname = mapping[asic_name_index]
                    single_objects["asic_port_name"] = mapping[asic_name_index]
            objects.append(single_objects)
    
    # Physical ports names from port_config.ini
    with open("./physical_ports_dut.json", "w") as outfile:
        json.dump(names, outfile)

    # Create json version of ini file
    with open("./port_config.json", "w") as outfile:
        json.dump(objects, outfile)

    return port_alias_to_name_map

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--device", help="device file [deprecate warning: use -i instead]", default=DEFAULT_DEVICECSV)
    parser.add_argument("-l", "--links", help="link file [deprecate warning: use -i instead]", default=DEFAULT_LINKCSV)
    parser.add_argument("-c", "--console", help="console connection file [deprecate warning: use -i instead]", default=DEFAULT_CONSOLECSV)
    parser.add_argument("-p", "--pdu", help="pdu connection file [deprecate warning: use -i instead]", default=DEFAULT_PDUCSV)
    parser.add_argument("-i", "--inventory", help="specify inventory namei to generate device/link/console/pdu file names, default none", default=None)
    parser.add_argument("-o", "--output", help="output xml file", required=True)
    parser.add_argument("-u", "--hwsku", help="hwsku of DUT")
    parser.add_argument("-q", "--port_config", help="path to port_config.ini if hwsku is not known")
    args = parser.parse_args()
    if args.hwsku == None and args.port_config == None :
        print("Error: either provie hwsku or path to port_config.ini file")
        exit()
    if args.port_config != None:
        port_alias_to_name_map = get_portmap(args.port_config)
    if args.hwsku != None:
        (port_alias_to_name_map, _) = get_port_alias_to_name_map(args.hwsku)
    names = []
    for _, name in port_alias_to_name_map.items():
        names.append(name)
    for i in range(len(names)):
        names[i] = names[i][8:]
        names[i] = int(names[i])
    names.sort()
    # Create json file of port_alias_to_name_map
    with open("./port_alias_to_name_map.json", "w") as outfile:
        json.dump(port_alias_to_name_map, outfile)
    device, links, console, pdu = get_file_names(args)
    mygraph = LabGraph(device, links, console, pdu, args.output, names )

    mygraph.read_devices()
    mygraph.read_links()
    mygraph.read_consolelinks()
    mygraph.read_pdulinks()
    mygraph.generate_dpg()
    mygraph.create_xml()


if __name__ == '__main__':
    main()
