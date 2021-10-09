#!/usr/bin/env python

import re
import yaml
import os
import traceback
import subprocess
import ipaddr as ipaddress
from operator import itemgetter
from itertools import groupby
from collections import defaultdict
import re

from ansible.parsing.dataloader import DataLoader
from ansible.inventory.manager import InventoryManager

DOCUMENTATION = '''
module: testbed_vm_info.py
Ansible_version_added:  2.0.0.2
short_description:   Gather all related VMs info
Description:
       When deploy testbed topology with VM connected to SONiC, gather neighbor VMs info for generating SONiC minigraph file
 options:
    base_vm:  base vm name defined in testbed.csv for the deployed topology; required: True
    topo:     topology name defined in testbed.csv for the deployed topology; required: True
    vm_file:  the virtual machine file path ; default: 'veos'

Ansible_facts:
    'neighbor_eosvm_mgmt':  all VM hosts management IPs
    'topoall':              topology information

'''

EXAMPLES = '''
    - name: gather vm information
      testbed_vm_info: base_vm='VM0100' topo='t1' vm_file='veos'
'''

### Here are the assumption/expectation of files to gather VM informations, if the file location or name changes, please modify it here
TOPO_PATH = 'vars/'
VM_INV_FILE = 'veos'
TGEN_MGMT_NETWORK = '10.65.32.0/24'


class TestbedVMFacts():
    """
    Retrieve testbed VMs management information that for a specified toplogy defined in testbed.csv

    """

    def __init__(self, toponame, vmbase, vmfile):
        CLET_SUFFIX = "-clet"
        toponame = re.sub(CLET_SUFFIX + "$", "", toponame)
        self.topofile = TOPO_PATH+'topo_'+toponame +'.yml'
        if vmbase != '':
            self.start_index = int(re.findall('VM(\d+)', vmbase)[0])
        else:
            self.start_index = 0
        self.vmhosts = {}
        self.vmfile = vmfile
        self.inv_mgr = InventoryManager(loader=DataLoader(), sources=self.vmfile)
        return


    def get_neighbor_eos(self):
        eos = {}
        with open(self.topofile) as f:
            vm_topology = yaml.load(f)
        self.topoall = vm_topology
        for  vm in vm_topology['topology']['VMs']:
            vm_index = int(vm_topology['topology']['VMs'][vm]['vm_offset'])+self.start_index
            eos[vm] = vm_index
        return eos


def main():
    module = AnsibleModule(
        argument_spec=dict(
            base_vm=dict(required=True, type='str'),
            topo=dict(required=True, type='str'),
            vm_file=dict(default=VM_INV_FILE, type='str')
        ),
        supports_check_mode=True
    )
    m_args = module.params
    topo_type = m_args['topo']
    if 'ptf' in topo_type:
        module.exit_json(ansible_facts={'neighbor_eosvm_mgmt': {}})
    try:
        vmsall = TestbedVMFacts(m_args['topo'], m_args['base_vm'], m_args['vm_file'])
        neighbor_eos = vmsall.get_neighbor_eos()
        tgen_mgmt_ips = list(ipaddress.IPNetwork(unicode(TGEN_MGMT_NETWORK)))
        for index, eos in enumerate(neighbor_eos):
            vmname = 'VM'+format(neighbor_eos[eos], '04d')
            if 'tgen' in topo_type:
                vmsall.vmhosts[eos] = str(tgen_mgmt_ips[index])
            elif vmname in vmsall.inv_mgr.hosts:
                vmsall.vmhosts[eos] = vmsall.inv_mgr.get_host(vmname).get_vars()['ansible_host']
            else:
                err_msg = "cannot find the vm " + vmname + " in VM inventory file, please make sure you have enough VMs for the topology you are using"
                module.fail_json(msg=err_msg)
        module.exit_json(ansible_facts={'neighbor_eosvm_mgmt':vmsall.vmhosts, 'topoall': vmsall.topoall})
    except (IOError, OSError):
        module.fail_json(msg="Can not find file "+vmsall.topofile+" or "+m_args['vm_file']+" or "+VM_INV_FILE)
    except Exception as e:
        module.fail_json(msg=traceback.format_exc())

from ansible.module_utils.basic import *
if __name__ == "__main__":
    main()

