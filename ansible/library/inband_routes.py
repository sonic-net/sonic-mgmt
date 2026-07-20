#!/usr/bin/python

from ansible.module_utils.basic import AnsibleModule
import ipaddress
import sys
import subprocess

DOCUMENTATION = '''
module: inband_routes
version_added:  "1.0"

short_description: add inband routes from PTF to DUT
description: add routes for inband connectivity to Loopback from the PTF to the DUT

Options:
    - option-name: loopback_ips
      description: list of loopback IPs to add
      required: True
    - option-name: vm_names
      description: list of VM names to use for routing
      required: True
    - option-name: convergence_data
      description: data used for mapping the VM IP address to actual address when using converged containers
      required: True
    - option-name: configuration
      description: fallback VM configuration data
      required: True

'''

EXAMPLES = '''
- name: Add IPv6 routes
  inband_routes:
    loopback_ips: "{{ topology['DUT']['loopback']['ipv6'] | default(['fc00:1::32']) }}"
    vm_names: "{{ topo_vms.keys() }}"
    convergence_data: "{{ convergence_data|default({}) }}"
    configuration: "{{ configuration }}"
'''


def configure_routes(loopback_ip, vm_names, convergence_data, configuration):
    command = ["ip", "route", "replace", loopback_ip, "metric", "100"]

    loopback_ip_object = ipaddress.ip_network(loopback_ip)
    af = "ipv6" if loopback_ip_object.version == 6 else "ipv4"

    for vm_name in vm_names:
        if convergence_data:
            rev_vrf_map = {}
            for dev, vrfs in convergence_data["convergence_mapping"].items():
                for vrf in vrfs:
                    rev_vrf_map[vrf] = dev

            vlan = convergence_data["ptf_backplane_addrs"][vm_name]["vlan"]

            host = rev_vrf_map[vm_name]
            addr = convergence_data["converged_peers"][host]["vrf"][vm_name]["Vlan{}".format(vlan)][af]
            command.extend(["nexthop", "via", addr.split("/")[0]])
        else:
            command.extend(["nexthop", "via", configuration[vm_name].bp_interface[af].split("/")[0]])

    subprocess.run(command, check=True)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            loopback_ips=dict(required=True, type='list', elements='str'),
            vm_names=dict(required=True, type='list', elements='str'),
            convergence_data=dict(required=True, type='dict'),
            configuration=dict(required=True, type='dict'),
        ),
        supports_check_mode=False)

    loopback_ips = module.params['loopback_ips']
    vm_names = module.params['vm_names']
    convergence_data = module.params['convergence_data']
    configuration = module.params['configuration']

    result = {}
    try:
        for loopback_ip in loopback_ips:
            configure_routes(loopback_ip, vm_names, convergence_data, configuration)
    except Exception:
        err = str(sys.exc_info())
        module.fail_json(msg="Error: %s" % err)

    module.exit_json(**result)


if __name__ == '__main__':
    main()
