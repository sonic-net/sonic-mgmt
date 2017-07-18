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
        This module try to find the correct port_config.ini for the hwsku and return Ansible ansible_facts.port_alias
        The definition of this mapping is specified in http://github.com/azure/sonic-buildimage/device
        docker-sonic-mgmt will gather and include the information from sonic-buildimage
    Input:
        hwsku

    Return Ansible_facts:
    port_alias:  SONiC interface name mapping to actual vendor specified name

'''

EXAMPLES = '''
    - name: get hardware interface alias name
      port_alias: hwsku='ACS-MSN2700'
'''

### TODO:  use sonic config sonic-cfggen to replace this port_alias module ###############
### Here are the expectation of files of device port_config.ini located, in case changed please modify it here 
FILE_PATH = '/usr/share/sonic/device'
PORTMAP_FILE = 'port_config.ini'

class SonicPortmap():
    """
    Retrieve SONiC device interface port alias mapping

    """
    def __init__(self, hwsku):
        self.filename = ''
        self.hwsku = hwsku
        self.portmap = dict()
        return

    def findfile(self):
        for (rootdir, dirnames, filenames) in os.walk(FILE_PATH):
            if self.hwsku in rootdir and len(dirnames) == 0 and PORTMAP_FILE in filenames:
                self.filename = rootdir+'/'+PORTMAP_FILE

    def get_portmap(self):
        self.findfile()
        if self.filename == '':
            raise Exception("Something wrong when trying to find the portmap file, either the hwsku is not available or file location is not correct")
        with open(self.filename) as f:
            lines = f.readlines()
            self.portmap['mapping'] = dict()
        for  line in lines:
            if 'Ethernet' in line:
                mapping = line.split()
                if len(mapping) < 3:
                    self.portmap['alias'] = False
                    self.portmap['mapping'] = {}
                    return
                else:
                    self.portmap['alias'] = True
                    self.portmap['mapping'][mapping[0]] = mapping[2]
        return

def main():
    module = AnsibleModule(
        argument_spec=dict(
            hwsku=dict(required=True, type='str')
        ),
        supports_check_mode=False
    )
    m_args = module.params
    try:
        allmap = SonicPortmap(m_args['hwsku'])
        allmap.get_portmap()
        module.exit_json(ansible_facts={'port_alias': allmap.portmap})
    except (IOError, OSError):
        module.fail_json(msg=allmap.portmap)
    except Exception:
        module.fail_json(msg=allmap.portmap)

def debugmain():
    allmap = SonicPortmap('Arista-7050-QX32')
    allmap.get_portmap()
    print allmap.portmap

from ansible.module_utils.basic import *
if __name__ == "__main__":
    #debugmain()
    main()
