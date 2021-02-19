#!/usr/bin/env python

from ansible.parsing.dataloader import DataLoader
from ansible.inventory.manager import InventoryManager

DOCUMENTATION = '''
module: vmhost_server_info.py
short_description:   Gather mgmt IP for given host server (like server_17)
Description:
       This plugin will parse the input vm_file and return mgmt IP for given host server.
 options:
    vmhost_server_name:  the name of vm_host server, like server_1; required: True
    vm_file:  the virtual machine file path ; default: 'veos'

Ansible_facts:
    'vmhost_server_address':  the IPv4 address for given vmhost server

'''

EXAMPLES = '''
    - name: gather vm_host server address
      vmhost_server_info: vmhost_server_name='server_1' vm_file='veos'
'''

# Here we assume that the group name of host server starts with 'vm_host_'.
VMHOST_PREFIX = "vm_host_"

VM_INV_FILE = 'veos'

def main():
    module = AnsibleModule(
        argument_spec=dict(
            vmhost_server_name=dict(required=True, type='str'),
            vm_file=dict(default=VM_INV_FILE, type='str')
        ),
        supports_check_mode=True
    )
    m_args = module.params
    vmhost_group_name = VMHOST_PREFIX + m_args['vmhost_server_name'].split('_')[-1]
    inv_mgr = InventoryManager(loader=DataLoader(), sources=m_args['vm_file'])
    all_hosts = inv_mgr.get_hosts(pattern=vmhost_group_name)
    if len(all_hosts) != 1:
        module.fail_json(msg="{} host servers are found in {}, which should be 1".format(len(all_hosts), vmhost_group_name))
    else:
        module.exit_json(ansible_facts={'vmhost_server_address':all_hosts[0].get_vars()['ansible_host']})

from ansible.module_utils.basic import *
if __name__ == "__main__":
    main()

