#!/usr/bin/env python

from ansible.module_utils.basic import AnsibleModule
import re
import yaml
import traceback
import ipaddress

from ansible.parsing.dataloader import DataLoader
from ansible.inventory.manager import InventoryManager

DOCUMENTATION = '''
module: testbed_vm_info.py
Ansible_version_added:  2.0.0.2
short_description: Gather all related VMs info
Description:
       When deploy testbed topology with VM connected to SONiC,
       gather neighbor VMs info for generating SONiC minigraph file
 options:
    base_vm:  base vm name defined in testbed.csv for the deployed topology; required: True
    topo:     topology name defined in testbed.csv for the deployed topology; required: True
    vm_file:  the virtual machine file path; default: 'veos'

Ansible_facts:
    'neighbor_eosvm_mgmt':  all VM hosts management IPs
    'topoall':              topology information

'''

EXAMPLES = '''
    - name: gather vm information
      testbed_vm_info: base_vm='VM0100' topo='t1' vm_file='veos'
'''

# Here are the assumption/expectation of files to gather VM information,
# if the file location or name changes, please modify it here
TOPO_PATH = 'vars/'
VM_INV_FILE = 'veos'
TGEN_MGMT_NETWORK = '10.65.32.0/24'


class TestbedVMFacts():
    """
    Retrieve testbed VMs management information that for a specified toplogy defined in testbed.yaml

    """

    def __init__(self, toponame, base_vm, vm_file):
        CLET_SUFFIX = "-clet"
        self.toponame = re.sub(CLET_SUFFIX + "$", "", toponame)
        self.topofile = TOPO_PATH + 'topo_' + self.toponame + '.yml'
        self.base_vm = base_vm
        self.vm_file = vm_file
        self.inv_mgr = InventoryManager(
            loader=DataLoader(), sources=self.vm_file)

    def get_neighbor_eos(self):
        eos = {}
        with open(self.topofile) as f:
            vm_topology = yaml.safe_load(f)
        self.topoall = vm_topology

        if len(self.base_vm) > 2:
            vm_start_index = int(self.base_vm[2:])
            vm_name_fmt = 'VM%0{}d'.format(len(self.base_vm) - 2)
        else:
            if 'tgen' in self.toponame:
                vm_start_index = 0
                vm_name_fmt = 'VM%05d'
            else:
                return eos

        for eos_name, eos_value in vm_topology['topology']['VMs'].items():
            vm_name = vm_name_fmt % (vm_start_index + eos_value['vm_offset'])
            eos[eos_name] = vm_name
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

    vm_mgmt_ip = {}
    try:
        vm_facts = TestbedVMFacts(
            m_args['topo'], m_args['base_vm'], m_args['vm_file'])
        neighbor_eos = vm_facts.get_neighbor_eos()

        tgen_mgmt_ips = list(ipaddress.ip_network(TGEN_MGMT_NETWORK.encode().decode()))
        for index, eos in enumerate(neighbor_eos):
            vm_name = neighbor_eos[eos]
            if 'tgen' in topo_type:
                vm_mgmt_ip[eos] = str(tgen_mgmt_ips[index])
            elif vm_name in vm_facts.inv_mgr.hosts:
                vm_mgmt_ip[eos] = vm_facts.inv_mgr.get_host(
                    vm_name).get_vars()['ansible_host']
            else:
                err_msg = "Cannot find the vm {} in VM inventory file {}, please make sure you have enough VMs" \
                          "for the topology you are using."
                err_msg.format(vm_name, vm_facts.vm_file)
                module.fail_json(msg=err_msg)
        module.exit_json(
            ansible_facts={'neighbor_eosvm_mgmt': vm_mgmt_ip, 'topoall': vm_facts.topoall})
    except (IOError, OSError):
        module.fail_json(msg='Can not find VM file {} or {}'.format(
            m_args['vm_file'], VM_INV_FILE))
    except Exception:
        module.fail_json(msg=traceback.format_exc())


if __name__ == "__main__":
    main()
