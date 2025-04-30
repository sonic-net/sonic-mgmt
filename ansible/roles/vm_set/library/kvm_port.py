#!/usr/bin/python

import re
import subprocess
from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = '''
module: kvm_port
version_added: "0.1"
author: Guohan Lu (gulv@microsoft.com)
short_description: Gather management and front panel ports from KVM-based DUT
'''

EXAMPLES = '''
- name: Get front panel and mgmt port for kvm vm
  kvm_port:
    vmname: "{{ dut_name }}"
'''


def main():

    module = AnsibleModule(argument_spec=dict(
        vmname=dict(required=True),
        front_panel_port_aliases=dict(required=True, type=list),
        midplane_port_aliases=dict(required=False, type=list, default=[]),
        inband_port_aliases=dict(required=False, type=list, default=[]),
    ))

    vmname = module.params['vmname']
    fp_port_aliases = module.params['front_panel_port_aliases']
    midplane_port_aliases = module.params['midplane_port_aliases']
    inband_port_aliases = module.params['inband_port_aliases']

    try:
        output = subprocess.check_output(
            "virsh domiflist %s" % vmname,
            env={"LIBVIRT_DEFAULT_URI": "qemu:///system"},
            shell=True).decode('utf-8')
    except subprocess.CalledProcessError:
        module.fail_json(msg="failed to iflist dom %s" % vmname)

    mgmt_port = None
    fp_ports = {}
    midplane_ports = []
    inband_ports = []

    lines = output.split('\n')[2:]  # the first two lines are table headers
    eth_interfaces = []
    for line in lines:
        fds = re.split(r'\s+', line.lstrip())
        if len(fds) != 5:
            continue
        if fds[1] == "ethernet":
            eth_interfaces.append(fds[0])

    if len(eth_interfaces) < 1 + len(fp_port_aliases) + len(midplane_port_aliases) + len(inband_port_aliases):
        module.fail_json(msg="No enough ethernet ports for {}\n{}\n{}\n{}".format(
            vmname, fp_port_aliases, midplane_port_aliases, inband_port_aliases))

    # extract mgmt port, fp_ports, midplane_ports(optional), inband_ports(optional)
    mgmt_port = eth_interfaces[0]
    eth_interfaces = eth_interfaces[1:]
    cur_fp_idx = 0
    for portinfo in fp_port_aliases:
        fp_ports[cur_fp_idx] = eth_interfaces[portinfo[1]]
        cur_fp_idx += 1
    for portinfo in midplane_port_aliases:
        midplane_ports.append(eth_interfaces[portinfo[1]])
    for portinfo in inband_port_aliases:
        inband_ports.append(eth_interfaces[portinfo[1]])

    module.exit_json(changed=False, ansible_facts={
                     'dut_mgmt_port': mgmt_port, 'dut_fp_ports': fp_ports,
                     'dut_midplane_ports': midplane_ports, 'dut_inband_ports': inband_ports})


if __name__ == "__main__":
    main()
