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

DOCUMENTATION='''
module: testbed_vm_info.py
Ansible_version_added:  2.0.0.2
short_description:   Gather all related VMs info 
Description:
       When deploy testbed topology with VM connected to SONiC, gather neighbor VMs info for generating SONiC minigraph file
 options:
    base_vm:  base vm name defined in testbed.csv for the deployed topology; required: True
    topo:     topology name defined in testbed.csv for the deployed topology; required: True

Ansible_facts:
    'neighbor_eosvm_mgmt':  all VM hosts management IPs 
    'topoall':              topology information

'''

EXAMPLES='''
    - name: gather vm information
      testbed_vm_info: base_vm='VM0100' topo='t1'
'''

### Here are the assumption/expectation of files to gather VM informations, if the file location or name changes, please modify it here 
TOPO_PATH = 'vars/'
VM_INV_FILE = 'veos'


class TestbedVMFacts():
    """
    Retrieve testbed VMs management information that for a specified toplogy defined in testbed.csv

    """

    def __init__(self, toponame, vmbase):
        self.topofile = TOPO_PATH+'topo_'+toponame +'.yml'
        self.start_index = int(re.findall('VM(\d+)', vmbase)[0])
        self.vmhosts = {}
        return


    def get_neighbor_eos(self):
        eos = {}
        with open(self.topofile) as f:
            vm_topology = yaml.load(f)
            f.close()
        self.topoall = vm_topology
        for  vm in vm_topology['topology']['VMs']:
            vm_index = int(vm_topology['topology']['VMs'][vm]['vm_offset'])+self.start_index
            eos[vm] = vm_index
        return eos


    def gather_veos_vm(self, eos_name, vm_index):
        vmname = 'VM'+format(vm_index, '04d')
        vmcmd = 'cat '+VM_INV_FILE+' | grep '+  vmname
        p = subprocess.Popen(vmcmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = p.communicate()
        rt_code = p.returncode
        if rt_code != 0 or stdout == '':
            msg="cannot find the VM=" +vmname+" in VM inventory file that is used to generate the minigraph, please make sure you have enouh VMs in inventory file for the VM ranges you specified"
            raise Exception(msg)
        vm_prop = stdout.split()
        if vmname == vm_prop[0] and 'ansible_host' in vm_prop[1]:
            self.vmhosts[eos_name] = vm_prop[1].split('=')[1]
        return 


def main():
    module = AnsibleModule(
        argument_spec=dict(
            base_vm=dict(required=True, type='str'),
            topo=dict(required=True, type='str'),
        ),
        supports_check_mode=False
    )
    m_args = module.params
    topo_type = m_args['topo'] 
    if 'ptf' in topo_type:
        module.exit_json(ansible_facts= {'neighbor_eosvm_mgmt': {}})
    try:
        vmsall = TestbedVMFacts(m_args['topo'], m_args['base_vm'])
        neighbor_eos = vmsall.get_neighbor_eos()
        for eos in neighbor_eos:
            vmsall.gather_veos_vm(eos, neighbor_eos[eos])
        module.exit_json(ansible_facts={'neighbor_eosvm_mgmt':vmsall.vmhosts, 'topoall': vmsall.topoall})
    except (IOError, OSError):
        module.fail_json(msg="Can not find file "+vmsall.topofile+" or "+VM_INV_FILE)
    except Exception as e:
        module.fail_json(msg=traceback.format_exc())

from ansible.module_utils.basic import *
if __name__== "__main__":
    main()


