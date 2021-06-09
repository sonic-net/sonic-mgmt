#!/usr/bin/env python

import csv
import sys
import os
import argparse
from lxml import etree

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
        #TODO:make generated xml file name as parameters in the future to make it more flexible
        self.devices = []
        self.links =  []
        self.consoles =  []
        self.pdus =  []
        self.devcsv = dev_csvfile
        self.linkcsv = link_csvfile
        self.conscsv = cons_csvfile
        self.pducsv = pdu_csvfile
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
            for link in csv_links:
                attrs = {}
                for key in link:
                    if key.lower() != 'vlanid' and key.lower() != 'vlanmode':
                        attrs[key]=link[key].decode('utf-8')
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
