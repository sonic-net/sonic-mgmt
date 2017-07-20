#!/usr/bin/env python
import csv, sys, os
from lxml import etree

DEVICECSV = 'sonic_lab_devices.csv'
LINKCSV = 'sonic_lab_links.csv'
LAB_CONNECTION_GRAPH_ROOT_NAME = 'LabConnectionGraph'
LAB_CONNECTION_GRAPH_DPGL2_NAME = 'DevicesL2Info'

class LabGraph(object):

    """ 
    This is used to create "graph" file of lab for all connections and vlan info from csv file
    We(both engineer and lab technician) maintian and modify the csv file to keep track of the lab
    infrastucture for Sonic development and testing environment. 
    """

    def __init__(self, dev_csvfile='', link_csvfile=''):
        #TODO:make generated xml file name as parameters in the future to make it more flexible
        self.devices = []
        self.links =  []
        self.devcsv = dev_csvfile
        self.linkcsv = link_csvfile
        self.png_xmlfile = 'str_sonic_png.xml'
        self.dpg_xmlfile = 'str_sonic_dpg.xml'
        self.one_xmlfile = 'lab_connection_graph.xml'
        self.pngroot = etree.Element('PhysicalNetworkGraphDeclaration')
        self.dpgroot = etree.Element('DataPlaneGraph')


    def read_devices(self):
        csv_dev = open(self.devcsv)
        csv_devices = csv.DictReader(csv_dev)
        devices_root = etree.SubElement(self.pngroot, 'Devices')
        for row in csv_devices:
            attrs = {}
            self.devices.append(row)
            for  key in row:
                if key.lower() != 'managementip':
                    attrs[key]=row[key].decode('utf-8')
            prod = etree.SubElement(devices_root, 'Device', attrs)
        csv_dev.close()
 
    def read_links(self):
        csv_file = open(self.linkcsv)
        csv_links = csv.DictReader(csv_file)
        links_root = etree.SubElement(self.pngroot, 'DeviceInterfaceLinks')
        for link in csv_links:
            attrs = {}
            for key in link:
                if key.lower() != 'vlanid' and key.lower() != 'vlanmode':
                    attrs[key]=link[key].decode('utf-8')
            prod = etree.SubElement(links_root, 'DeviceInterfaceLink', attrs)
            self.links.append(link)
        csv_file.close()
 
    def generate_dpg(self):
        for dev in self.devices:
            hostname = dev.get('Hostname', '')
            managementip = dev.get('ManagementIp', '')
            if hostname and 'fanout' in dev['Type'].lower():
                ###### Build Management interface IP here, if we create each device indivial minigraph file, we may comment this out 
                l3inforoot = etree.SubElement(self.dpgroot, 'DevicesL3Info', {'Hostname': hostname})
                etree.SubElement(l3inforoot, 'ManagementIPInterface', {'Name': 'ManagementIp', 'Prefix': managementip})
                ####### Build L2 information Here
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
        root=etree.Element(LAB_CONNECTION_GRAPH_ROOT_NAME)
        root.append(self.pngroot)
        root.append(self.dpgroot)
        result = etree.tostring(root, pretty_print=True)
        onexml.write(result)

def main():

    mygraph = LabGraph(DEVICECSV, LINKCSV)

    mygraph.read_devices()
    mygraph.read_links()
    mygraph.generate_dpg()
    mygraph.create_xml()


if __name__ == '__main__':
    main()

