#!/usr/bin/python

from ansible.module_utils.basic import *

DOCUMENTATION = '''
module: cisco_8000e_port
version_added: "0.1"
author: Rafal Skorka (skorka@cisco.com)
short_description: Gather management and front panel ports from 8000e-sonic DUT
This is a stub, currently returns hardcoded values
'''

EXAMPLES = '''
- name: Get front panel and mgmt port for 8000e-sonic sim
  cisco_8000e_port:
    vmname: "{{ dut_name }}"
'''


def main():

    module = AnsibleModule(argument_spec=dict(
        vmname = dict(required=False),
    ))

    vmname = module.params['vmname']

    mgmt_port = None
    fp_ports = {}

    for i in range(0,64):
        fp_ports[i] = "%s-%i" % (vmname, i+1)

    mgmt_port = "%s-0" % vmname

    module.exit_json(changed=False, ansible_facts={'dut_mgmt_port': mgmt_port, 'dut_fp_ports': fp_ports})

if __name__ == "__main__":
    main()
