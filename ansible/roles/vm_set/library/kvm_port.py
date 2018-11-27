#!/usr/bin/python

import re
import sys
import time
import subprocess
from ansible.module_utils.basic import *

DOCUMENTATION = '''
'''

def main():

    module = AnsibleModule(argument_spec=dict(
        vmname = dict(required=True),
    ))

    vmname = module.params['vmname']

    try:
        output = subprocess.check_output(
                "virsh domiflist %s" % vmname, 
                env={"LIBVIRT_DEFAULT_URI": "qemu:///system"}, 
                shell=True)
    except subprocess.CalledProcessError:
        module.fail_json(msg="failed to iflist dom %s" % vmname)

    mgmt_port = None
    fp_ports = []

    for l in output.split('\n'):
        fds = re.split('\s+', l)
        if len(fds) != 5:
            continue
        if fds[1] == "ethernet":
            if mgmt_port == None:
                mgmt_port = fds[0]
            else:
                fp_ports.append(fds[0])

    if mgmt_port == None:
        module.fail_json(msg="failed to find mgmt port")

    module.exit_json(changed=False, ansible_facts={'dut_mgmt_port': mgmt_port, 'dut_fp_ports': fp_ports})

if __name__ == "__main__":
    main()
