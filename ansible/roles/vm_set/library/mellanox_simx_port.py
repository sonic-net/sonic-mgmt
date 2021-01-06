#!/usr/bin/python

from ansible.module_utils.basic import *

DOCUMENTATION = '''
module: mellanox_simx_port
version_added: "0.1"
author: Mykola Faryma (mykolaf@mellanox.com)
short_description: Gather management and front panel ports from simx-based DUT
This is a stub, currently returns hardcoded values
'''

EXAMPLES = '''
- name: Get front panel and mgmt port for SimX in Docker
  mellanox_simx_port:
    vmname: "{{ dut_name }}"
'''

def main():

    module = AnsibleModule(argument_spec=dict(
        vmname = dict(required=False),
    ))

    mgmt_port = None
    fp_ports = {}
    
    for i in range(1,33):
        fp_ports[i] = "v000_p{}".format(i)

    mgmt_port = "tap0"

    module.exit_json(changed=False, ansible_facts={'dut_mgmt_port': mgmt_port, 'dut_fp_ports': fp_ports})

if __name__ == "__main__":
    main()
