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
    vmhost_server_name = m_args["vmhost_server_name"]
    vm_file = m_args["vm_file"]

    inv_mgr = InventoryManager(loader=DataLoader(), sources=vm_file)

    all_hosts = inv_mgr.get_hosts(pattern=vmhost_server_name)
    if len(all_hosts) == 0:
        module.fail_json(msg="No host matches {} in inventory file {}".format(vmhost_server_name, vm_file))
    else:
        for host in all_hosts:
            if host.name.startswith('VM'):
                continue
            module.exit_json(ansible_facts={"vmhost_server_address": host.get_vars()["ansible_host"]})

        module.fail_json(msg="Unable to find IP address of host server {} in inventory file {}".format(vmhost_server_name, vm_file))

from ansible.module_utils.basic import *
if __name__ == "__main__":
    main()
