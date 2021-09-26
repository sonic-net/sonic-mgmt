#!/usr/bin/env python

import re
import os
import traceback
import subprocess
from operator import itemgetter
from itertools import groupby
from collections import defaultdict

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
        The definition of this mapping is specified in http://github.com/azure/sonic-buildimage/device
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

MACHINE_CONF = '/host/machine.conf'
ONIE_PLATFORM_KEY = 'onie_platform'
ABOOT_PLATFORM_KEY = 'aboot_platform'

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
                if key == ONIE_PLATFORM_KEY or key == ABOOT_PLATFORM_KEY:
                    return value
        return None

    def get_portconfig_path(self, asic_id=None):
        platform = self.get_platform_type()
        if platform is None:
            return None
        if asic_id is None:
            portconfig = os.path.join(FILE_PATH, platform, self.hwsku, PORTMAP_FILE)
        else:
            portconfig = os.path.join(FILE_PATH, platform, self.hwsku, str(asic_id), PORTMAP_FILE)
        if os.path.exists(portconfig):
            return portconfig
        return None

    def get_portmap(self, asic_id=None, include_internal=False,
                    hostname=None, switchid=None):
        aliases = []
        portmap = {}
        aliasmap = {}
        portspeed = {}
        # Front end interface asic names
        front_panel_asic_ifnames = []
        # All asic names
        asic_if_names = []
        sysports = []
        port_coreid_index = -1
        port_core_portid_index = -1
        num_voq_index = -1
        # default to ASIC0 as minigraph.py parsing code has that assumption.
        asic_name = "ASIC0" if asic_id is None else "ASIC" + str(asic_id)

        filename = self.get_portconfig_path(asic_id)
        if filename is None:
            raise Exception("Something wrong when trying to find the portmap file, either the hwsku is not available or file location is not correct")
        with open(filename) as f:
            lines = f.readlines()
        alias_index = -1
        speed_index = -1
        role_index = -1
        asic_name_index = -1
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
                    if role == 'Ext' or (role == "Int" and include_internal):
                        add_port = True
                        aliases.append(alias)
                        portmap[name] = alias
                        aliasmap[alias] = name
                        if role == "Ext" and (asic_name_index != -1) and (len(mapping) > asic_name_index):
                            asicifname = mapping[asic_name_index]
                            front_panel_asic_ifnames.append(asicifname)
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
            start_switchid=dict(type='int', required=False)
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
        # ASIC interface names of front panel interfaces
        front_panel_asic_ifnames = []
        # { asic_name: [ asic interfaces] }
        asic_if_names = {}

        if 'card_type' in m_args and m_args['card_type'] == 'supervisor':
           module.exit_json(ansible_facts={'port_alias': aliases,
                                           'port_name_map': portmap,
                                           'port_alias_map': aliasmap,
                                           'port_speed': portspeed,
                                           'front_panel_asic_ifnames': front_panel_asic_ifnames,
                                           'asic_if_names': asic_if_names,
                                           'sysports': sysports})
           return
        allmap = SonicPortAliasMap(m_args['hwsku'])
        start_switchid = 0
        if  'start_switchid' in m_args and m_args['start_switchid'] != None:
           start_switchid = int(m_args['start_switchid'])
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
            if asic_id is not None:
                switchid = start_switchid + asic_id
            if num_asic == 1:
                asic_id = None
            (aliases_asic, portmap_asic, aliasmap_asic, portspeed_asic, front_panel_asic, asicifnames_asic,
             sysport_asic) = allmap.get_portmap(asic_id, include_internal, hostname, switchid)
            if aliases_asic is not None:
                aliases.extend(aliases_asic)
            if portmap_asic is not None:
                portmap.update(portmap_asic)
            if aliasmap_asic is not None:
                aliasmap.update(aliasmap_asic)
            if portspeed_asic is not None:
                portspeed.update(portspeed_asic)
            if front_panel_asic is not None:
                front_panel_asic_ifnames.extend(front_panel_asic)
            if asicifnames_asic is not None:
                asic = 'ASIC' + str(asic_id)
                asic_if_names[asic] = asicifnames_asic
            if sysport_asic is not None:
                sysports.extend(sysport_asic)
        module.exit_json(ansible_facts={'port_alias': aliases,
                                        'port_name_map': portmap,
                                        'port_alias_map': aliasmap,
                                        'port_speed': portspeed,
                                        'front_panel_asic_ifnames': front_panel_asic_ifnames,
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
