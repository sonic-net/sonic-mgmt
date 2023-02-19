#!/usr/bin/env python

import re
import os
import traceback
import subprocess
import json
import ast
import csv
from operator import itemgetter
from itertools import groupby
from collections import defaultdict
from collections import OrderedDict

try:
    from sonic_py_common import multi_asic
except ImportError:
    print("Failed to import multi_asic")

DOCUMENTATION = '''
module: port_alias.py
Ansible_version_added:  2.0.0.2
short_description:   Find SONiC device port alias mapping if there is alias mapping
Description:
        Minigraph file is using SONiC device alias to describe the interface name, it's vendor and and hardware platform dependent
        This module is used to find the correct port_config.ini for the hwsku and return Ansible ansible_facts.port_alias
        The definition of this mapping is specified in http://github.com/sonic-net/sonic-buildimage/device
        You should build docker-sonic-mgmt from sonic-buildimage and run Ansible from sonic-mgmt docker container
        For multi-asic platforms, port_config.ini for each asic will be parsed to get the port_alias information.
        When bringing up the testbed, port-alias will only contain external interfaces, so that vs image can come up with
        external interfaces.
    Input:
        hwsku num_asic

    Return Ansible_facts:
    port_alias:  SONiC interface name or SONiC interface alias if alias is available

'''

EXAMPLES = '''
    - name: get hardware interface name
      port_alias: hwsku='ACS-MSN2700' num_asic=1
'''

RETURN = '''
      ansible_facts{
        port_alias: [Ethernet0, Ethernet4, ....],
        port_speed: {'Ethernet0':'40000', 'Ethernet4':'40000', ......]
      }
'''

### Here are the expectation of files of device port_config.ini located, in case changed please modify it here
FILE_PATH = '/usr/share/sonic/device'
PORTMAP_FILE = 'port_config.ini'
ALLOWED_HEADER = ['name', 'lanes', 'alias', 'index', 'asic_port_name', 'role', 'speed',
                  'coreid', 'coreportid', 'numvoq']

PLATFORM_FILE = 'platform.json'
HWSKU_FILE = 'hwsku.json'
LINKS_FILE = '/tmp/sonic_lab_links.csv'
MACHINE_CONF = '/host/machine.conf'
ONIE_PLATFORM_KEY = 'onie_platform'
ABOOT_PLATFORM_KEY = 'aboot_platform'
NVIDIA_BF_PLATFORM_KEY = 'bf_platform'

PLATFORM_KEYS = [ONIE_PLATFORM_KEY, ABOOT_PLATFORM_KEY, NVIDIA_BF_PLATFORM_KEY]

KVM_PLATFORM = 'x86_64-kvm_x86_64-r0'

class SonicPortAliasMap():
    """
    Retrieve SONiC device interface port alias mapping and port speed if they are definded

    """
    def __init__(self, hwsku):
        self.hwsku = hwsku
        return

    def get_platform_type(self):
        if not os.path.exists(MACHINE_CONF):
            return KVM_PLATFORM
        with open(MACHINE_CONF) as machine_conf:
            for line in machine_conf:
                tokens = line.split('=')
                key = tokens[0].strip()
                value = tokens[1].strip()
                if key in PLATFORM_KEYS: 
                    return value
        return None

    def get_portconfig_path(self, slotid=None, asic_id=None):
        platform = self.get_platform_type()
        if platform is None:
            return None
        if asic_id is None or asic_id == '':
            portconfig = os.path.join(FILE_PATH, platform, self.hwsku, PORTMAP_FILE)
        elif slotid is None or slotid == '':
            portconfig = os.path.join(FILE_PATH, platform, self.hwsku, str(asic_id), PORTMAP_FILE)
        else:
            portconfig = os.path.join(FILE_PATH, platform, self.hwsku, str(slotid), str(asic_id), PORTMAP_FILE)
        if os.path.exists(portconfig):
            return portconfig
        return None

    def get_platform_path(self):
        platform = self.get_platform_type()
        if platform is None:
            return None
        platform_path = os.path.join(FILE_PATH, platform, PLATFORM_FILE)
        if os.path.exists(platform_path):
            return platform_path
        return None

    def get_hwsku_path(self):
        platform = self.get_platform_type()
        if platform is None:
            return None
        hwsku_path = os.path.join(FILE_PATH, platform, self.hwsku, HWSKU_FILE)
        if os.path.exists(hwsku_path):
            return hwsku_path
        return None

    def get_portmap_from_platform_hwsku(self, platform_file, hwsku_file, aliases, portmap, aliasmap, portspeed, speeds_list):
        decoder = json.JSONDecoder(object_pairs_hook=OrderedDict)
        brkout_pattern = r'(\d{1,3})x(\d{1,3}G)(\[\d{1,3}G\])?(\((\d{1,3})\))?'
        with open(platform_file) as f:
            data = json.load(f, object_pairs_hook=OrderedDict)
            platform_dict = decoder.decode(json.dumps(data))
        with open(hwsku_file) as f:
            data = json.load(f)
            hwsku_dict = ast.literal_eval(json.dumps(data))
        for interface in platform_dict["interfaces"]:
            if interface not in hwsku_dict["interfaces"]:
                raise Exception("interface {} not in hwsku dict".format(interface))
            lanes = platform_dict["interfaces"][interface]['lanes']
            breakout_mode = hwsku_dict["interfaces"][interface]["default_brkout_mode"]
            alias_list = platform_dict["interfaces"][interface]['breakout_modes'][breakout_mode]

            # Asymmetric breakout mode
            if re.search("\+", breakout_mode) is not None:
                breakout_parts = breakout_mode.split("+")
                match_list = [re.match(brkout_pattern, i).groups() for i in breakout_parts]
            # Symmetric breakout mode
            else:
                match_list = [re.match(brkout_pattern, breakout_mode).groups()]

            offset = 0
            parent_intf_id = int(re.search("Ethernet(\d+)", interface).group(1))
            for k in match_list:
                if k is not None:
                    num_lane_used, speed, assigned_lane = k[0], k[1], k[4]

                    # In case of symmetric mode
                    if assigned_lane is None:
                        assigned_lane = len(lanes.split(","))

                    parent_intf_id = int(offset)+int(parent_intf_id)
                    alias_position = 0 + int(offset)//int(num_lane_used)

                    step = int(assigned_lane)//int(num_lane_used)
                    for i in range(0,int(assigned_lane), step):

                        intf_name = "Ethernet" + str(parent_intf_id)
                        alias = alias_list[alias_position]

                        alias_indexes = platform_dict["interfaces"][interface]['index'].split(",")
                        aliases.append((str(alias), alias_indexes[0]))

                        portmap[intf_name] = str(alias)
                        aliasmap[str(alias)] = intf_name

                        if speeds_list:
                            portspeed[alias] = speeds_list.get(alias)
                        else:
                            if speed:
                                speed_pat = re.search("^((\d+)G|\d+)$", speed.upper())
                                if speed_pat is None:
                                    raise Exception('{} speed is not Supported...'.format(speed))
                                speed_G, speed_orig = speed_pat.group(2), speed_pat.group(1)
                                if speed_G:
                                    portspeed[alias] = str(int(speed_G)*1000)
                                else:
                                    portspeed[alias] = speed_orig
                            else:
                                raise Exception('Regex return for speed is None...')

                        parent_intf_id += step
                        alias_position += 1

                    parent_intf_id = 0
                    offset = int(assigned_lane) + int(offset)

    def get_portmap(self, asic_id=None, include_internal=False,
                    hostname=None, switchid=None, slotid=None, speeds_list=None):
        aliases = []
        portmap = {}
        aliasmap = {}
        portspeed = {}
        # Front end interface asic names
        front_panel_asic_ifnames = {}
        # All asic names
        asic_if_names = []
        sysports = []
        port_coreid_index = -1
        port_core_portid_index = -1
        num_voq_index = -1
        # default to Asic0 as minigraph.py parsing code has that assumption.
        asic_name = "Asic0" if asic_id is None else "asic" + str(asic_id)
        # if platform.json and hwsku.json exist, than get portmap from hwsku
        platform_file = self.get_platform_path()
        hwsku_file = self.get_hwsku_path()
        if platform_file and hwsku_file:
            self.get_portmap_from_platform_hwsku(platform_file, hwsku_file, aliases, portmap, aliasmap, portspeed, speeds_list)
            return (aliases, portmap, aliasmap, portspeed, front_panel_asic_ifnames, asic_if_names,
                sysports)
        # platform.json or hwsku.json does not exist so get portmap from port_config.ini
        filename = self.get_portconfig_path(slotid, asic_id)
        if filename is None:
            raise Exception("Something wrong when trying to find the portmap file, either the hwsku is not available or file location is not correct")
        with open(filename) as f:
            lines = f.readlines()
        alias_index = -1
        speed_index = -1
        role_index = -1
        asic_name_index = -1
        port_index = -1
        while len(lines) != 0:
            line = lines.pop(0)
            if re.match('^#', line):
                title=re.sub('#', '', line.strip().lower()).split()
                for text in title:
                    if text in ALLOWED_HEADER:
                        index = title.index(text)
                        if 'alias' in text:
                            alias_index = index
                        if 'speed' in text:
                            speed_index = index
                        if 'role' in text:
                            role_index = index
                        if 'asic_port_name' in text:
                            asic_name_index = index
                        if 'coreid' in text:
                            port_coreid_index = index
                        if 'coreportid' in text:
                            port_core_portid_index = index
                        if 'numvoq' in text:
                            num_voq_index = index
                        if 'index' in text:
                            port_index = index
            else:
                #added support to parse recycle port
                if re.match('^Ethernet', line) or re.match('^Recirc', line):
                    mapping = line.split()
                    name = mapping[0]
                    sysport = {}
                    sysport['name'] = name
                    sysport['hostname'] = hostname
                    sysport['asic_name'] = asic_name
                    sysport['switchid'] = switchid
                    if (role_index != -1) and (len(mapping) > role_index):
                        role = mapping[role_index]
                    else:
                        role = 'Ext'
                    if alias_index != -1 and len(mapping) > alias_index:
                        alias = mapping[alias_index]
                    else:
                        alias = name
                    add_port = False
                    if role in {"Ext", "Inb", "Rec"} or (role == "Int" and include_internal):
                        add_port = True
                        aliases.append((alias, -1 if port_index == -1 or len(mapping) <= port_index else mapping[port_index]))
                        portmap[name] = alias
                        aliasmap[alias] = name
                        if role == "Ext" and (asic_name_index != -1) and (len(mapping) > asic_name_index):
                            asicifname = mapping[asic_name_index]
                            front_panel_asic_ifnames[alias] = asicifname
                    if (asic_name_index != -1) and (len(mapping) > asic_name_index):
                        asicifname = mapping[asic_name_index]
                        asic_if_names.append(asicifname)
                    if (speed_index != -1) and (len(mapping) > speed_index):
                        speed = mapping[speed_index]
                        sysport['speed'] = speed
                        if add_port is True:
                           portspeed[alias] = speed
                    if (port_coreid_index != -1) and (len(mapping) > port_coreid_index):
                        coreid = mapping[port_coreid_index]
                        sysport['coreid'] = coreid
                    if (port_core_portid_index != -1) and (len(mapping) > port_core_portid_index):
                        core_portid = mapping[port_core_portid_index]
                        sysport['core_portid'] = core_portid
                    if (num_voq_index != -1) and (len(mapping) > num_voq_index):
                        voq = mapping[num_voq_index]
                        sysport['num_voq'] = voq
                        sysport['name'] = name
                        sysport['hostname'] = hostname
                        sysport['asic_name'] = asic_name
                        sysport['switchid'] = switchid
                        sysports.append(sysport)
        if len(sysports) > 0:
            sysport = {}
            sysport['name'] = 'Cpu0'
            sysport['asic_name'] = asic_name
            sysport['speed'] = 10000
            sysport['switchid'] = switchid
            sysport['coreid'] = 0
            sysport['core_portid'] = 0
            sysport['num_voq'] = voq
            sysport['hostname'] = hostname
            sysports.insert(0, sysport)

        return (aliases, portmap, aliasmap, portspeed, front_panel_asic_ifnames, asic_if_names,
                sysports)

def main():
    module = AnsibleModule(
        argument_spec=dict(
            hwsku=dict(required=True, type='str'),
            num_asic=dict(type='int', required=False),
            include_internal=dict(required=False, type='bool', default=False),
            card_type=dict(type='str', required=False),
            hostname=dict(type='str', required=False),
            switchids=dict(type='list', required=False),
            slotid=dict(type='str', required=False)
        ),
        supports_check_mode=True
    )
    m_args = module.params
    try:
        aliases = []
        portmap = {}
        aliasmap = {}
        portspeed = {}
        sysports = []
        # Map of ASIC interface names to front panel interfaces
        front_panel_asic_ifnames = {}
        # { asic_name: [ asic interfaces] }
        asic_if_names = {}

        if 'card_type' in m_args and m_args['card_type'] == 'supervisor':
           module.exit_json(ansible_facts={'port_alias': aliases,
                                           'port_name_map': portmap,
                                           'port_alias_map': aliasmap,
                                           'port_speed': portspeed,
                                           'front_panel_asic_ifnames': [],
                                           'asic_if_names': asic_if_names,
                                           'sysports': sysports})
           return
        allmap = SonicPortAliasMap(m_args['hwsku'])
        switchids = None
        slotid = None
        speeds_list = None
        if os.path.exists(LINKS_FILE):
            with open(LINKS_FILE) as f:
                data = csv.DictReader(f)
                speeds_list = {row['StartPort']:row['BandWidth'] for row in data if row['StartDevice'] == m_args['hostname']}
        if 'switchids' in m_args and m_args['switchids'] != None and len(m_args['switchids']):
           switchids = m_args['switchids']

        if 'slotid' in m_args and m_args['slotid'] != None:
           slotid = m_args['slotid']
        # When this script is invoked on sonic-mgmt docker, num_asic
        # parameter is passed.
        if m_args['num_asic'] is not None:
            num_asic = m_args['num_asic']
        else:
            # When this script is run on the device, num_asic parameter
            # is not passed.
            try:
                num_asic = multi_asic.get_num_asics()
            except Exception as e:
                num_asic = 1
        # Modify KVM platform string based on num_asic
        global KVM_PLATFORM
        if num_asic == 4:
            KVM_PLATFORM = "x86_64-kvm_x86_64_4_asic-r0"
        if num_asic == 6:
            KVM_PLATFORM = "x86_64-kvm_x86_64_6_asic-r0"

        switchid = 0
        include_internal = False
        if 'include_internal' in m_args:
            include_internal = m_args['include_internal']
        hostname = ""
        if 'hostname' in m_args:
            hostname = m_args['hostname']
        for asic_id in range(num_asic):
            if switchids and asic_id is not None:
                switchid = switchids[asic_id]
            if num_asic == 1:
                asic_id = None
            (aliases_asic, portmap_asic, aliasmap_asic, portspeed_asic, front_panel_asic, asicifnames_asic,
             sysport_asic) = allmap.get_portmap(asic_id, include_internal, hostname, switchid, slotid, speeds_list)
            if aliases_asic is not None:
                aliases.extend(aliases_asic)
            if portmap_asic is not None:
                portmap.update(portmap_asic)
            if aliasmap_asic is not None:
                aliasmap.update(aliasmap_asic)
            if portspeed_asic is not None:
                portspeed.update(portspeed_asic)
            if front_panel_asic is not None:
                front_panel_asic_ifnames.update(front_panel_asic)
            if asicifnames_asic is not None:
                asic = 'ASIC' + str(asic_id)
                asic_if_names[asic] = asicifnames_asic
            if sysport_asic is not None:
                sysports.extend(sysport_asic)

        # Sort the Interface Name needed in multi-asic
        aliases.sort(key=lambda x: int(x[1]))
        # Get ASIC interface names list based on sorted aliases
        front_panel_asic_ifnames_list = []
        for k in aliases:
            if k[0] in front_panel_asic_ifnames:
                front_panel_asic_ifnames_list.append(front_panel_asic_ifnames[k[0]])

        module.exit_json(ansible_facts={'port_alias': [k[0] for k in aliases],
                                        'port_name_map': portmap,
                                        'port_alias_map': aliasmap,
                                        'port_speed': portspeed,
                                        'front_panel_asic_ifnames': front_panel_asic_ifnames_list,
                                        'asic_if_names': asic_if_names,
                                        'sysports': sysports})

    except (IOError, OSError) as e:
        fail_msg = "IO error" + str(e)
        module.fail_json(msg=fail_msg)
    except Exception as e:
        fail_msg = "failed to find the correct port config for "+m_args['hwsku'] + str(e)
        module.fail_json(msg=fail_msg)

from ansible.module_utils.basic import *
if __name__ == "__main__":
    main()
