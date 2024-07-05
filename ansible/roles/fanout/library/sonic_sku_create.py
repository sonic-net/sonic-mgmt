#!/usr/bin/env python3

"""
usage: sonic_sku_create.py [-h] [-v] [-f FILE] [-m [MINIGRAPH_FILE]] [-b BASE]
                           [-r] [-k HWSKU]
                           [-p] [-vv]
Create a new SKU

optional arguments:
  -h, --help            Show this help message and exit
  -v, --version         Show program's version number and exit
  -f FILE, --file FILE  SKU definition from xml file. -f OR -m must be provided when creating a new SKU
  -m [MINIGRAPH_FILE], --minigraph_file [MINIGRAPH_FILE]
                        SKU definition from minigraph file. -f OR -m must be provided when creating a new SKU
  -b BASE, --base BASE  SKU base definition
  -r, --remove          Remove SKU folder
  -k HWSKU, --hwsku HWSKU
                        SKU name to be used when creating a new SKU or for  L2 configuration mode
  -p, --print           Print port_config.ini without creating a new SKU
  -vv, --verbose        Verbose output


"""

import argparse
import itertools
import json
import os
import re
import subprocess
import traceback
import sys
import shutil
import copy
from collections import OrderedDict

from tabulate import tabulate
from lxml import etree as ET
from lxml.etree import QName
from sonic_py_common.general import check_output_pipe

minigraph_ns = "Microsoft.Search.Autopilot.Evolution"
minigraph_ns1 = "http://schemas.datacontract.org/2004/07/Microsoft.Search.Autopilot.Evolution"
INTERFACE_KEY = "Ethernet"

# port_config.ini header
PORTCONFIG_HEADER = ["# name", "lanes", "alias", "index", "speed"]
platform_4 = ['x86_64-mlnx_lssn2700-r0', 'x86_64-mlnx_msn2010-r0', 'x86_64-mlnx_msn2100-r0', 'x86_64-mlnx_msn2410-r0',
              'x86_64-mlnx_msn2700-r0', 'x86_64-mlnx_msn2740-r0', 'x86_64-mlnx_msn3700c-r0', 'x86_64-mlnx_msn3700-r0',
              'x86_64-mlnx_msn3800-r0']
platform_8 = ['x86_64-mlnx_msn4600c-r0', 'x86_64-mlnx_msn4700-r0']

bko_dict_4 = {
    "1x100": {"lanes": 4, "speed": 100000, "step": 4, "bko": 0, "name": "etp"},
    "1x40":  {"lanes": 4, "speed": 40000,  "step": 4, "bko": 0, "name": "etp"},
    "1x50":  {"lanes": 4, "speed": 50000,  "step": 4, "bko": 0, "name": "etp"},
    "1x25":  {"lanes": 4, "speed": 25000,  "step": 4, "bko": 0, "name": "etp"},
    "1x10":  {"lanes": 4, "speed": 10000,  "step": 4, "bko": 0, "name": "etp"},
    "1x1":   {"lanes": 4, "speed": 1000,   "step": 4, "bko": 0, "name": "etp"},
    "4x10":  {"lanes": 4, "speed": 10000,  "step": 1, "bko": 1, "name": "etp"},
    "4x25":  {"lanes": 4, "speed": 25000,  "step": 1, "bko": 1, "name": "etp"},
    "2x50":  {"lanes": 4, "speed": 50000,  "step": 2, "bko": 1, "name": "etp"},
}

bko_dict_8 = {
    "1x400": {"lanes": 8, "speed": 400000, "step": 8, "bko": 0, "name": "etp"},
    "2x200": {"lanes": 8, "speed": 200000, "step": 4, "bko": 1, "name": "etp"},
    "2x100": {"lanes": 8, "speed": 100000, "step": 4, "bko": 1, "name": "etp"},
    "4x100": {"lanes": 8, "speed": 100000, "step": 2, "bko": 1, "name": "etp"},
    "4x50":  {"lanes": 8, "speed": 50000,  "step": 2, "bko": 1, "name": "etp"},
    "4x25":  {"lanes": 4, "speed": 25000,  "step": 1, "bko": 1, "name": "etp"},
    "4x10":  {"lanes": 4, "speed": 10000,  "step": 1, "bko": 1, "name": "etp"},
}


class SkuCreate(object):
    """
    Tool for SKU creator
    """

    PORT_ALIAS_PATTERNS = (
        re.compile(r"^etp(?P<port_index>\d+)(?P<lane>[a-d]?)"),
        re.compile(r"^Ethernet(?P<port_index>\d+)(/)?(?(2)(?P<lane>[1-4]+))")
    )

    def __init__(self):

        self.portconfig_dict = {}
        self.platform_specific_dict = {"x86_64-mlnx_msn2700-r0": self.msn2700_specific}
        self.default_lanes_per_port = []
        self.platform = None
        self.base_lanes = None
        self.fpp = []
        self.fpp_split = {}
        self.num_of_fpp = 0
        self.sku_name = None
        self.default_sku_path = None
        self.base_sku_name = None
        self.base_sku_dir = None
        self.base_file_path = None
        self.new_sku_dir = None
        self.print_mode = False
        self.remove_mode = False
        self.verbose = None
        self.bko_dict = {}

    def sku_def_parser(self, sku_def):
        # Parsing XML sku definition file to extract Interface speed and InterfaceName(alias)
        # <etp<#><a/b/c/d>|<Ethernet<#>/<#> to be used to analyze split configuration
        # Rest of the fields are used as placeholders for portconfig_dict [name,lanes,SPEED,ALIAS,index]
        try:
            f = open(str(sku_def), "r")
        except IOError:
            print("Couldn't open file: " + str(sku_def), file=sys.stderr)
            sys.exit(1)
        element = ET.parse(f)

        root = element.getroot()
        if (self.verbose):
            print("tag=%s, attrib=%s" % (root.tag, root.attrib))
        self.sku_name = root.attrib["HwSku"]
        self.new_sku_dir = self.default_sku_path+"/" + self.sku_name + '/'
        idx = 1
        for child in root:
            if child.tag == "Ethernet":
                for interface in child:
                    for eth_iter in interface.iter():
                        if eth_iter is not None:
                            self.portconfig_dict[idx] = [
                                "Ethernet"+str(idx), [1, 2, 3, 4], eth_iter.get("InterfaceName"), str(idx),
                                eth_iter.get("Speed")
                            ]
                            if (self.verbose):
                                print("sku_def_parser:portconfig_dict[", idx, "] -> ", self.portconfig_dict[idx])
                            idx += 1
        f.close()

    def parse_deviceinfo(self, meta, hwsku):
        # Parsing minigraph sku definition file to extract Interface speed and
        # InterfaceName(alias) <etp<#><a/b/c/d> to be used to analyze split configuration
        # Rest of the fields are used as placeholders for portconfig_dict [name,lanes,SPEED,ALIAS,index]
        idx = 1
        match = None
        for device_info in meta.findall(str(QName(minigraph_ns, "DeviceInfo"))):
            dev_sku = device_info.find(str(QName(minigraph_ns, "HwSku"))).text
            if dev_sku == hwsku:
                match = True
                interfaces = device_info.find(str(QName(minigraph_ns, "EthernetInterfaces"))).\
                    findall(str(QName(minigraph_ns1, "EthernetInterface")))

                for interface in interfaces:
                    alias = interface.find(str(QName(minigraph_ns, "InterfaceName"))).text
                    speed = interface.find(str(QName(minigraph_ns, "Speed"))).text
                    port_name = "Ethernet" + str(idx)
                    self.portconfig_dict[idx] = [port_name, [1, 2, 3, 4], alias, idx, speed]
                    if (self.verbose):
                        print("parse_device_info(minigraph)--> ", self.portconfig_dict[idx])
                    idx += 1

        if match is None:
            raise ValueError("Couldn't find a SKU ", hwsku, "in minigraph file")

    def minigraph_parser(self, minigraph_file):
        # Function to parse minigraph XML file and generate SKU file (port_config.ini) by populating information
        # regarding the ports that are extracted from minigraph file
        root = ET.parse(minigraph_file).getroot()
        if (self.verbose):
            print("tag=%s, attrib=%s" % (root.tag, root.attrib))
        hwsku_qn = QName(minigraph_ns, "HwSku")
        for child in root:
            if (self.verbose):
                print("TAG: ", child.tag, "TEXT: ", child.text)
            if child.tag == str(hwsku_qn):
                hwsku = child.text

        self.new_sku_dir = self.default_sku_path + "/" + hwsku + '/'

        for child in root:
            if (self.verbose):
                print("tag=%s, attrib=%s" % (child.tag, child.attrib))
            if child.tag == str(QName(minigraph_ns, "DeviceInfos")):
                self.parse_deviceinfo(child, hwsku)

    def check_json_lanes_with_bko(self, data, port_idx):
        # Function to find matching entry in bko_dict that matches Port details from config_db.json file
        port_str = "Ethernet{:d}".format(port_idx)
        port_dict = []
        port_bmp = 1
        port_dict = data['PORT'].get(port_str)
        if "speed" in port_dict:
            port_speed = port_dict.get("speed")
            int_port_speed = int(port_speed)
        else:
            print(port_str, "does not contain speed key, Exiting...", file=sys.stderr)
            sys.exit(1)
        for i in range(1, self.base_lanes):
            curr_port_str = "Ethernet{:d}".format(port_idx+i)
            if curr_port_str in data['PORT']:
                curr_port_dict = data['PORT'].get(curr_port_str)
                if "speed" in curr_port_dict:
                    curr_speed = curr_port_dict.get("speed")
                else:
                    print(curr_port_str, "does not contain speed key, Exiting...", file=sys.stderr)
                    sys.exit(1)
                if port_speed != curr_speed:
                    print(curr_port_str, "speed is different from that of ", port_str, ", Exiting...", file=sys.stderr)
                    sys.exit(1)
                if "alias" not in curr_port_dict:
                    print(curr_port_str, "does not contain alias key, Exiting...", file=sys.stderr)
                    sys.exit(1)
                if "lanes" not in curr_port_dict:
                    print(curr_port_str, "does not contain lanes key, Exiting...", file=sys.stderr)
                    sys.exit(1)
                port_bmp |= (1 << i)

        for entry in self.bko_dict:
            bko_dict_entry = self.bko_dict[entry]
            pattern = '^([0-9]{1,})x([0-9]{1,})'
            m = re.match(pattern, entry)
            bko_speed = int(m.group(2))

            if ((bko_speed * 1000) == int_port_speed):
                bko_step = bko_dict_entry["step"]
                bko_bmp = 0
                for i in range(0, self.base_lanes, bko_step):
                    bko_bmp |= (1 << i)
                if bko_bmp == port_bmp:
                    return entry
        return None

    def write_json_lanes_to_pi_list(self, data, port_idx, port_split, pi_list):
        # Function to write line of port_config.ini corresponding to a port
        step = self.bko_dict[port_split]["step"]
        for i in range(0, self.base_lanes, step):
            curr_port_str = "Ethernet{:d}".format(port_idx+i)
            curr_port_dict = data['PORT'].get(curr_port_str)
            curr_speed = curr_port_dict.get("speed")
            curr_alias = curr_port_dict.get("alias")
            curr_lanes = curr_port_dict.get("lanes")
            curr_index = int(port_idx/self.base_lanes) + 1
            curr_port_info = [curr_port_str, curr_lanes, curr_alias, curr_index, curr_speed]
            pi_list.append(curr_port_info)
        return

    def json_file_parser(self, json_file):
        # Function to generate SKU file from config_db.json file by
        # extracting port related information from the config_db.json file
        pi_list = []
        with open(json_file) as f:
            data = json.load(f, object_pairs_hook=OrderedDict)
        meta_dict = data['DEVICE_METADATA']['localhost']
        self.sku_name = meta_dict.get("hwsku")
        self.new_sku_dir = self.default_sku_path + "/" + self.sku_name + '/'
        if self.remove_mode:
            self.remove_sku_dir()
            return
        self.create_sku_dir()
        print("Created a new sku (Location: " + self.new_sku_dir+")")
        self.ini_file = self.new_sku_dir + "/" + "port_config.ini"
        new_file = self.ini_file + ".new"
        f_out = open(new_file, 'w')
        header_str = "#name           lanes                alias       index     speed\n"
        f_out.write(header_str)

        # data['PORT'] is already an OrderedDict, we can not sort it, so we create
        # pi_list - list of port info items and then sort it
        for key, value in data['PORT'].items():
            pattern = '^Ethernet([0-9]{1,})'
            m = re.match(pattern, key)
            if m is None:
                print("Port Name ", key, " is not valid, Exiting...", file=sys.stderr)
                sys.exit(1)
            port_idx = int(m.group(1))

            if port_idx % self.base_lanes == 0:
                result = self.check_json_lanes_with_bko(data, port_idx)
                if result is not None:
                    self.write_json_lanes_to_pi_list(data, port_idx, result, pi_list)
            else:
                continue
        # sort the list with interface name
        pi_list.sort(key=lambda x: (int(re.search(('^Ethernet([0-9]{1,})'), x[0]).group(1))))

        for port_info in pi_list:
            out_str = "{:15s} {:20s} {:11s} {:9s} {:10s}\n".format(port_info[0], port_info[1], port_info[2],
                                                                   str(port_info[3]), str(port_info[4]))
            if self.print_mode:
                print(out_str)
            else:
                f_out.write(out_str)
            if self.verbose and (self.print_mode is False):
                print(out_str)
        f_out.close()
        self.port_config_split_analyze(self.ini_file)
        self.form_port_config_dict_from_ini(self.ini_file)
        self.platform_specific()
        shutil.copy(new_file, self.ini_file)
        return

    def parse_platform_from_config_db_file(self, config_file):
        with open(config_file) as f:
            data = json.load(f, object_pairs_hook=OrderedDict)
        meta_dict = data['DEVICE_METADATA']['localhost']
        platform = meta_dict.get("platform")
        pattern = '^x86_64-mlnx_msn([0-9]{1,}[a-zA-Z]?)-r0'
        m = re.match(pattern, platform)
        if m is None:
            print("Platform Name ", platform, " is not valid, Exiting...", file=sys.stderr)
            sys.exit(1)
        self.platform = platform

    def port_config_split_analyze(self, ini_file):
        # Internal function to populate fpp_split tuple with from a port information
        new_file = ini_file + ".new"
        f_in = open(new_file, 'r')

        idx = 1
        for line in f_in.readlines():
            line.strip()
            if len(line.rstrip()) == 0:
                continue

            if re.search("^#", line) is not None:
                continue

            line = line.lstrip()
            line_arr = line.split()
            pattern = '^etp([0-9]{1,})([a-d]?)'
            m = re.match(pattern, line_arr[2])
            if int(m.group(1)) not in self.fpp_split:
                self.fpp_split[int(m.group(1))] = [[line_arr[2]], [idx]]  # 1
            else:
                self.fpp_split[int(m.group(1))][0].append(line_arr[2])  # += 1
                self.fpp_split[int(m.group(1))][1].append(idx)
            idx += 1
        f_in.close()

    def form_port_config_dict_from_ini(self, ini_file):
        # Internal function to populate portconfig_dict from port_config.ini file
        new_file = ini_file + ".new"
        f_in = open(new_file, 'r')

        idx = 1
        for line in f_in.readlines():
            line.strip()
            if len(line.rstrip()) == 0:
                continue

            if re.search("^#", line) is not None:
                continue

            line = line.lstrip()
            line_arr = line.split()
            if len(line_arr) == 5:
                self.portconfig_dict[idx] = ["Ethernet"+str(idx), [1, 2, 3, 4], line_arr[2], str(idx), line_arr[4]]
                idx += 1
            else:
                print("port_config.ini file does not contain all fields, Exiting...", file=sys.stderr)
                sys.exit(1)

        f_in.close()

    def break_in_ini(self, ini_file, port_name, port_split):
        # Function to split or unsplit a port in Port_config.ini file
        lanes_str_result = ""
        pattern = '^([0-9]{1,})x([0-9]{1,})'
        m = re.match(pattern, port_split)
        if m is None:
            print("Port split format ", port_split, " is not valid, Exiting...", file=sys.stderr)
            sys.exit(1)
        if port_split in self.bko_dict:
            step = self.bko_dict[port_split]["step"]
            speed = self.bko_dict[port_split]["speed"]
            base_lanes = self.bko_dict[port_split]["lanes"]
            bko = self.bko_dict[port_split]["bko"]
        else:
            print("Port split ", port_split, " is undefined for this platform, Exiting...", file=sys.stderr)
            sys.exit(1)

        port_found = False
        pattern = '^Ethernet([0-9]{1,})'
        m = re.match(pattern, port_name)
        if m is None:
            print("Port Name ", port_name, " is not valid, Exiting...", file=sys.stderr)
            sys.exit(1)
        port_idx = int(m.group(1))
        if port_idx % base_lanes != 0:
            print(port_name, " is not base port, Exiting...", file=sys.stderr)
            sys.exit(1)

        bak_file = ini_file + ".bak"
        shutil.copy(ini_file, bak_file)

        new_file = ini_file + ".new"

        f_in = open(bak_file, 'r')
        f_out = open(new_file, 'w')

        title = []
        alias_arr = ['a', 'b', 'c', 'd']

        for line in f_in.readlines():
            line.strip()
            if len(line.rstrip()) == 0:
                continue

            if re.search("^#", line) is not None:
                # The current format is: # name lanes alias index speed
                # Where the ordering of the columns can vary
                if len(title) == 0:
                    title = line.split()[1:]
                    print(title)
                f_out.write(line)
                continue

            orig_line = line
            line = line.lstrip()
            line_port = line.split()[0]
            line_alias = line.split()[2]
            pattern = '^etp([0-9]{1,})([a-d]?)'
            m = re.match(pattern, line_alias)
            alias_index = int(m.group(1))

            if line_port == port_name:
                port_found = True
                matched_alias_index = alias_index
                pattern = '^Ethernet([0-9]{1,})'
                m = re.match(pattern, line_port)
                line_port_index = int(m.group(1))
                line_lanes = line.split()[1]
                lane_index = int(line_lanes.split(',')[0])

                # find split partition
                for i in range(0, base_lanes, step):
                    port_str = "Ethernet{:d}".format(line_port_index + i)
                    lanes_str = "{:d}".format(lane_index + i)
                    if step > 1:
                        for j in range(1, step):
                            lanes_str += ",{:d}".format(lane_index + i + j)
                    if bko == 0:
                        alias_str = "etp{:d}".format(alias_index)
                    else:
                        alias_str = "etp{:d}{:s}".format(alias_index, alias_arr[int(i/step)])
                    index_str = "{:d}".format(alias_index)
                    lanes_str_result = lanes_str_result + ":" + lanes_str
                    out_str = "{:15s} {:20s} {:11s} {:9s} {:10s}\n".format(port_str, lanes_str, alias_str, index_str,
                                                                           str(speed))
                    f_out.write(out_str)
            else:
                if port_found:
                    if alias_index == matched_alias_index:
                        continue
                    else:
                        f_out.write(orig_line)

                else:
                    f_out.write(orig_line)

        f_in.close()
        f_out.close()
        return lanes_str_result

    def break_in_cfg(self, cfg_file, port_name, port_split, lanes_str_result):
        # Function to split or unsplit a port in config_db.json file
        if not os.access(os.path.dirname(cfg_file), os.W_OK):
            print("Skipping config_db.json updates for a write permission issue")
            return

        bak_file = cfg_file + ".bak"
        shutil.copy(cfg_file, bak_file)

        new_file = cfg_file + ".new"

        with open(bak_file) as f:
            data = json.load(f)

        pattern = '^Ethernet([0-9]{1,})'
        m = re.match(pattern, port_name)
        port_idx = int(m.group(1))
        mtu = 9100

        for port_index in range(port_idx, port_idx+self.base_lanes):
            port_str = "Ethernet" + str(port_index)

            if data['PORT'].get(port_str) is not None:
                port_instance = data['PORT'].get(port_str)
                if "mtu" in port_instance:
                    mtu = port_instance.get("mtu")
                data['PORT'].pop(port_str)
                print("Removed Port instance:  ", port_str, port_instance)
                print("Please remove port ", port_str, " configurations that are part of other features")

        port_inst = {}
        j = 1
        lanes_arr = lanes_str_result.split(':')
        step = self.bko_dict[port_split]["step"]
        alias_arr = ['a', 'b', 'c', 'd']
        pattern = '^([0-9]{1,})x([0-9]{1,})'
        m = re.match(pattern, port_split)
        speed = int(m.group(2))
        bko = self.bko_dict[port_split]["bko"]

        for i in range(0, self.base_lanes, step):
            port_str = "Ethernet{:d}".format(port_idx + i)
            lanes_str = lanes_arr[j]
            j += 1

            if bko == 0:
                alias_str = "etp{:d}".format(int(port_idx/self.base_lanes)+1)
            else:
                alias_str = "etp{:d}{:s}".format(int(port_idx/self.base_lanes)+1, alias_arr[int(i/step)])
            port_inst["lanes"] = lanes_str
            port_inst["alias"] = alias_str
            port_inst["speed"] = speed*1000
            port_inst["mtu"] = mtu

            xxx = copy.deepcopy(port_inst)
            data['PORT'][port_str] = xxx
            print(port_str, data['PORT'][port_str])

        with open(new_file, 'w') as outfile:
            json.dump(data, outfile, indent=4, sort_keys=True)
        shutil.copy(new_file, cfg_file)

        print("--------------------------------------------------------")

    def break_a_port(self, port_name, port_split):
        # Function to split or unsplit a port based on user input in both port_config.ini file and config_db.json file
        new_file = self.ini_file + ".new"
        lanes_str_result = self.break_in_ini(self.ini_file, port_name, port_split)
        self.port_config_split_analyze(self.ini_file)
        self.form_port_config_dict_from_ini(self.ini_file)
        self.platform_specific()
        shutil.copy(new_file, self.ini_file)
        if lanes_str_result is None:
            print("break_in_ini function returned empty lanes string, Exiting...", file=sys.stderr)
            sys.exit(1)
        self.break_in_cfg(self.cfg_file, port_name, port_split, lanes_str_result)

    def _parse_interface_alias(self, alias):
        """Analyze the front panel port index and split index based on the alias."""
        for alias_pattern in self.PORT_ALIAS_PATTERNS:
            m = alias_pattern.match(alias)
            if m:
                return m.group("port_index"), m.group("lane")
        return None, None

    def split_analyze(self):
        # Analyze the front panel ports split  based on the interfaces alias names
        # fpp_split is a hash with key=front panel port and values is a list of lists ([alias],[index])
        alias_index = PORTCONFIG_HEADER.index('alias')
        for idx, ifc in self.portconfig_dict.items():
            pi, _ = self._parse_interface_alias(ifc[alias_index])
            pi = int(pi)
            if pi not in self.fpp_split:
                self.fpp_split[pi] = [[ifc[alias_index]], [idx]]  # 1
            else:
                self.fpp_split[pi][0].append(str(ifc[alias_index]))  # += 1
                self.fpp_split[pi][1].append(idx)
                if (self.verbose):
                    print("split_analyze -> ", pi, " : ", self.fpp_split[pi])
        self.num_of_fpp = len(list(self.fpp_split.keys()))

    def get_default_lanes(self):
        # Internal function to get lanes of the ports according to the base default SKU
        try:
            with open(self.base_file_path, "r") as f:
                lines = f.readlines()
                data_index = 0
                while not lines[data_index].strip() or lines[data_index].startswith("#"):
                    data_index = data_index + 1
                line_header = lines[data_index-1].strip("#\n ").split()
                if line_header[0] == "#":
                    del line_header[0]  # if hashtag is in a different column, remove it to align column header and data
                alias_index = line_header.index('alias')
                lanes_index = line_header.index('lanes')
                for line in lines[data_index:]:
                    if not line.strip() or line.startswith("#"):
                        continue
                    line_arr = line.split()
                    pi, _ = self._parse_interface_alias(line_arr[alias_index])
                    pi = int(pi)
                    self.default_lanes_per_port.insert(pi - 1, line_arr[lanes_index])
                    if (self.verbose):
                        print("get_default_lanes -> ", pi, " : ", self.default_lanes_per_port[pi - 1])

        except IOError:
            print("Could not open file " + self.base_file_path, file=sys.stderr)
            sys.exit(1)

    def set_lanes(self):
        # set lanes and index per interfaces based on split
        lanes_index = PORTCONFIG_HEADER.index('lanes')
        index_index = PORTCONFIG_HEADER.index('index')
        name_index = PORTCONFIG_HEADER.index('# name')

        for fp, values in self.fpp_split.items():
            splt_arr = sorted(values[0])
            idx_arr = sorted(values[1])

            splt = len(splt_arr)
            lanes = [_.strip() for _ in self.default_lanes_per_port[fp - 1].split(",")]
            lanes_count = len(lanes)
            if lanes_count % splt != 0:
                print("Lanes(%s) could not be evenly splitted by %d." % (self.default_lanes_per_port[fp - 1], splt))
                sys.exit(1)

            # split the lanes
            it = iter(lanes)
            lanes_splitted = list(iter(lambda: tuple(itertools.islice(it, lanes_count // splt)), ()))

            if (splt == 1):
                self.portconfig_dict[idx_arr[0]][lanes_index] = ",".join(lanes_splitted[0])
                self.portconfig_dict[idx_arr[0]][index_index] = str(fp)
                self.portconfig_dict[idx_arr[0]][name_index] = "Ethernet"+str((fp-1)*4)
                if (self.verbose):
                    print("set_lanes -> FP: ", fp, "Split: ", splt)
                    print("PortConfig_dict ", idx_arr[0], ":", self.portconfig_dict[idx_arr[0]])
            elif (splt == 2):
                self.portconfig_dict[idx_arr[0]][lanes_index] = ",".join(lanes_splitted[0])
                self.portconfig_dict[idx_arr[1]][lanes_index] = ",".join(lanes_splitted[1])
                self.portconfig_dict[idx_arr[0]][index_index] = str(fp)
                self.portconfig_dict[idx_arr[1]][index_index] = str(fp)
                self.portconfig_dict[idx_arr[0]][name_index] = "Ethernet"+str((fp-1)*4)
                self.portconfig_dict[idx_arr[1]][name_index] = "Ethernet"+str((fp-1)*4+2)
                if (self.verbose):
                    print("set_lanes -> FP: ", fp, "Split: ", splt)
                    print("PortConfig_dict ", idx_arr[0], ":", self.portconfig_dict[idx_arr[0]])
                    print("PortConfig_dict ", idx_arr[1], ":", self.portconfig_dict[idx_arr[1]])
            elif (splt == 4):
                self.portconfig_dict[idx_arr[0]][lanes_index] = ",".join(lanes_splitted[0])
                self.portconfig_dict[idx_arr[1]][lanes_index] = ",".join(lanes_splitted[1])
                self.portconfig_dict[idx_arr[2]][lanes_index] = ",".join(lanes_splitted[2])
                self.portconfig_dict[idx_arr[3]][lanes_index] = ",".join(lanes_splitted[3])
                self.portconfig_dict[idx_arr[0]][index_index] = str(fp)
                self.portconfig_dict[idx_arr[1]][index_index] = str(fp)
                self.portconfig_dict[idx_arr[2]][index_index] = str(fp)
                self.portconfig_dict[idx_arr[3]][index_index] = str(fp)
                self.portconfig_dict[idx_arr[0]][name_index] = "Ethernet"+str((fp-1)*4)
                self.portconfig_dict[idx_arr[1]][name_index] = "Ethernet"+str((fp-1)*4+1)
                self.portconfig_dict[idx_arr[2]][name_index] = "Ethernet"+str((fp-1)*4+2)
                self.portconfig_dict[idx_arr[3]][name_index] = "Ethernet"+str((fp-1)*4+3)
                if (self.verbose):
                    print("set_lanes -> FP: ", fp, "Split: ", splt)
                    print("PortConfig_dict ", idx_arr[0], ":", self.portconfig_dict[idx_arr[0]])
                    print("PortConfig_dict ", idx_arr[1], ":", self.portconfig_dict[idx_arr[1]])
                    print("PortConfig_dict ", idx_arr[2], ":", self.portconfig_dict[idx_arr[2]])
                    print("PortConfig_dict ", idx_arr[3], ":", self.portconfig_dict[idx_arr[3]])
        self.platform_specific()

    def create_port_config(self):
        # create a port_config.ini file based on the sku definition
        if not os.path.exists(self.new_sku_dir):
            print("Error - path:", self.new_sku_dir, " doesn't exist", file=sys.stderr)
            sys.exit(1)

        try:
            f = open(self.new_sku_dir+"port_config.ini", "w+")
        except IOError:
            print("Could not open file " + self.new_sku_dir + "port_config.ini", file=sys.stderr)
            sys.exit(1)
        header = PORTCONFIG_HEADER  # ["name", "lanes", "alias", "index"]
        port_config = []
        for line in self.portconfig_dict.values():
            port_config.append(line)

        port_config.sort(key=lambda x: (int(re.search((r'\d+'), x[0]).group(0))))  # sort the list with interface name
        f.write(tabulate(port_config, header, tablefmt="plain"))
        f.close()

    def print_port_config(self):
        # print a port_config.ini file based on the sku definition
        header = PORTCONFIG_HEADER  # ["name", "lanes", "alias", "index"]
        port_config = []
        for line in self.portconfig_dict.values():
            port_config.append(line)

        port_config.sort(key=lambda x: (int(re.search((r'\d+'), x[0]).group(0))))  # sort the list with interface name
        print(tabulate(port_config, header, tablefmt="plain"))

    def create_sku_dir(self):
        # create a new SKU directory based on the base SKU
        if (os.path.exists(self.new_sku_dir)):
            print("SKU directory: " + self.new_sku_dir +
                  " already exists\n Please use -r flag to remove the SKU dir first", file=sys.stderr)
            sys.exit(1)
        try:
            shutil.copytree(self.base_sku_dir, self.new_sku_dir)
        except OSError as e:
            print(str(e), file=sys.stderr)

    def remove_sku_dir(self):
        # remove SKU directory
        if (self.new_sku_dir == self.base_sku_dir):
            print("Removing the base SKU" + self.new_sku_dir + " is not allowed", file=sys.stderr)
            sys.exit(1)
        try:
            if not os.path.exists(self.new_sku_dir):
                print("Trying to remove a SKU " + self.new_sku_dir + " that doesn't exists, Ignoring -r command")
            while True:
                answer = input("You are about to permanently delete the SKU "
                               + self.new_sku_dir+" !! \nDo you want to continue (Yes/No)?")
                if (answer == "Yes" or answer == "No"):
                    break
                else:
                    print("Valid answers are Yes or No")
            if (answer == "Yes"):
                shutil.rmtree(self.new_sku_dir)
                print("SKU directory: " + self.new_sku_dir + " was removed")
            else:
                print("SKU directory: " + self.new_sku_dir + " was NOT removed")
        except OSError as e:
            print(str(e), file=sys.stderr)

    def platform_specific(self):
        # Function that checks for Platform specific restrictions
        func = self.platform_specific_dict.get(self.platform, lambda: "nothing")
        return func()

    def msn2700_specific(self):
        # Function that implements the check for platform restrictions of 2700 platform
        for fp, values in self.fpp_split.items():
            splt_arr = sorted(values[0])
            splt = len(splt_arr)
            try:
                if ((fp % 2) == 1 and splt == 4):
                    next_fp = fp+1
                    if (next_fp not in self.fpp_split):
                        continue
                    next_fp_idx_arr = sorted(self.fpp_split[next_fp][1])
                    for i in next_fp_idx_arr:
                        if (self.verbose):
                            print("msn2700_specific -> Removing ", self.portconfig_dict[i])
                        self.portconfig_dict.pop(i)
                    print("MSN2700 - Front panel port ", next_fp, " should be removed due to port ", fp, "Split by 4")
                    raise ValueError()
                elif ((fp % 2) == 0 and splt == 4):
                    print("MSN2700 -  even front panel ports (", fp, ") are not allowed to split by 4")
                    raise ValueError()
            except ValueError:
                print("Error - Illegal split by 4 ", file=sys.stderr)
                sys.exit(1)


def main(argv):
    parser = argparse.ArgumentParser(description='Create a new SKU',
                                     formatter_class=argparse.RawTextHelpFormatter)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-f', '--file', action='store', nargs=1,
                       help='SKU definition from xml file. -f OR -m or -j must be provided when creating a new SKU',
                       default=None)
    group.add_argument('-m', '--minigraph_file', action='store', nargs='?',
                       help='SKU definition from minigraph file.'
                            ' -f OR -m or -j must be provided when creating a new SKU',
                       const="/etc/sonic/minigraph.xml")
    group.add_argument('-j', '--json_file', action='store', nargs=1,
                       help='SKU definition from config_db.json file.'
                            ' -f OR -m OR -j must be provided when creating a new SKU',
                       default=None)
    group.add_argument('-s', '--port_split', action='store', nargs=2, help='port name and split', default=None)
    parser.add_argument('-b', '--base', action='store', help='SKU base definition', default=None)
    parser.add_argument('-r', '--remove', action='store_true', help='Remove SKU folder')
    parser.add_argument('-k', '--hwsku', action='store',
                        help='SKU name to be used when creating a new SKU or for  L2 configuration mode', default=None)
    parser.add_argument('-p', '--print', action='store_true', help='Print port_config.ini without creating a new SKU',
                        default=False)
    parser.add_argument('--verbose', action='store_true', help='Verbose output', default=False)
    parser.add_argument('-d', '--default_sku_path', action='store', nargs=1, help='Specify Default SKU path',
                        default=None)
    parser.add_argument('-q', '--port_split_path', action='store', nargs=1, help='Specify Port split path',
                        default=None)
    parser.add_argument('-v', '--version', action='version', version='%(prog)s 1.0')

    args = parser.parse_args()

    try:
        sku = SkuCreate()
        sku.verbose = args.verbose
        if (args.verbose):
            print("ARGS: ", args)
        if args.default_sku_path:
            sku.default_sku_path = args.default_sku_path[0]
        else:
            try:
                sku.platform = subprocess.check_output(["sonic-cfggen", "-H", "-v",
                                                        "DEVICE_METADATA.localhost.platform"], text=True)
                sku.platform = sku.platform.rstrip()
            except KeyError:
                print("Couldn't find platform info in CONFIG_DB DEVICE_METADATA", file=sys.stderr)
                sys.exit(1)
            sku.default_sku_path = '/usr/share/sonic/device/' + sku.platform

        if args.base:
            sku.base_sku_name = args.base
        else:
            f = open(sku.default_sku_path + '/' + "default_sku", "r")
            sku.base_sku_name = f.read().split()[0]

        sku.base_sku_dir = sku.default_sku_path + '/' + sku.base_sku_name + '/'
        sku.base_file_path = sku.base_sku_dir + "port_config.ini"

        if args.file:
            sku.sku_def_parser(args.file[0])
        elif args.minigraph_file:
            sku.minigraph_parser(args.minigraph_file)
        elif args.json_file:
            if sku.platform is None:
                sku.parse_platform_from_config_db_file(args.json_file[0])
            if sku.platform in platform_4:
                sku.base_lanes = 4
                sku.bko_dict = bko_dict_4
            else:
                sku.base_lanes = 8
                sku.bko_dict = bko_dict_8

            if args.remove:
                sku.remove_mode = True
            if args.print:
                sku.print_mode = True
            sku.cfg_file = "/etc/sonic/config_db.json"
            sku.json_file_parser(args.json_file[0])
            return
        elif args.port_split:
            if args.port_split_path:
                sku.ini_file = args.port_split_path[0] + "/port_config.ini"
                sku.cfg_file = args.port_split_path[0] + "/config_db.json"
                sku.parse_platform_from_config_db_file(sku.cfg_file)
            else:
                try:
                    sku_name = check_output_pipe(["show", "platform", "summary"], ["grep", "HwSKU"]).rstrip().split()[1]
                except KeyError:
                    print("Couldn't find HwSku info in Platform summary", file=sys.stderr)
                    sys.exit(1)
                sku.ini_file = sku.default_sku_path + "/" + sku_name + "/port_config.ini"
                sku.cfg_file = "/etc/sonic/config_db.json"

            if sku.platform in platform_4:
                sku.base_lanes = 4
                sku.bko_dict = bko_dict_4
            else:
                sku.base_lanes = 8
                sku.bko_dict = bko_dict_8
            sku.break_a_port(args.port_split[0], args.port_split[1])
            return

        if args.file or args.minigraph_file:
            if args.remove:
                sku.remove_sku_dir()
                return
            sku.get_default_lanes()
            sku.split_analyze()
            sku.set_lanes()
            if args.print:
                sku.print_port_config()
            else:
                sku.create_sku_dir()
                sku.create_port_config()
                print("Created a new sku (Location: " + sku.new_sku_dir+")")

    except Exception:
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main(sys.argv)
