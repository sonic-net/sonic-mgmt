#!/usr/bin/env python

import re
import os
import traceback
import subprocess
from operator import itemgetter
from itertools import groupby
from collections import defaultdict

DOCUMENTATION = '''
module: port_alias.py
Ansible_version_added:  2.0.0.2
short_description:   Find SONiC device port alias mapping if there is alias mapping
Description:
        Minigraph file is using SONiC deivce alias to describe the interface name, it's vendor and and hardware platform dependent
        This module is used to find the correct port_config.ini for the hwsku and return Ansible ansible_facts.port_alias
        The definition of this mapping is specified in http://github.com/azure/sonic-buildimage/device
        You should build docker-sonic-mgmt from sonic-buildimage and run Ansible from sonic-mgmt docker container
    Input:
        hwsku

    Return Ansible_facts:
    port_alias:  SONiC interface name or SONiC interface alias if alias is available

'''

EXAMPLES = '''
    - name: get hardware interface name
      port_alias: hwsku='ACS-MSN2700'
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
ALLOWED_HEADER = ['name', 'lanes', 'alias', 'index', 'speed']

class SonicPortAliasMap():
    """
    Retrieve SONiC device interface port alias mapping and port speed if they are definded

    """
    def __init__(self, hwsku):
        self.filename = ''
        self.hwsku = hwsku
        return

    def findfile(self):
        for (rootdir, dirnames, filenames) in os.walk(FILE_PATH, followlinks=True):
            if self.hwsku == rootdir.split('/')[-1] and len(dirnames) == 0 and PORTMAP_FILE in filenames:
                self.filename = rootdir + '/' + PORTMAP_FILE

    def get_portmap(self):
        aliases = []
        portmap = {}
        aliasmap = {}
        portspeed = {}
        self.findfile()
        if self.filename == '':
            raise Exception("Something wrong when trying to find the portmap file, either the hwsku is not available or file location is not correct")
        with open(self.filename) as f:
            lines = f.readlines()
        alias_index = -1
        speed_index = -1
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
            else:
                if re.match('^Ethernet', line):
                    mapping = line.split()
                    name = mapping[0]
                    if alias_index != -1 and len(mapping) > alias_index:
                        alias = mapping[alias_index]
                    else:
                        alias = name
                    aliases.append(alias)
                    portmap[name] = alias
                    aliasmap[alias] = name
                    if speed_index != -1:
                        portspeed[alias] = mapping[speed_index]

        return (aliases, portmap, aliasmap, portspeed)

def main():
    module = AnsibleModule(
        argument_spec=dict(
            hwsku=dict(required=True, type='str')
        ),
        supports_check_mode=True
    )
    m_args = module.params
    try:
        allmap = SonicPortAliasMap(m_args['hwsku'])
        (aliases, portmap, aliasmap, portspeed) = allmap.get_portmap()
        module.exit_json(ansible_facts={'port_alias': aliases,
                                        'port_name_map': portmap,
                                        'port_alias_map': aliasmap,
                                        'port_speed': portspeed})
    except (IOError, OSError), e:
        fail_msg = "IO error" + str(e)
        module.fail_json(msg=fail_msg)
    except Exception, e:
        fail_msg = "failed to find the correct port config for "+m_args['hwsku'] + str(e)
        module.fail_json(msg=fail_msg)

from ansible.module_utils.basic import *
if __name__ == "__main__":
    main()
