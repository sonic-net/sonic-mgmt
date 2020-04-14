#!/usr/bin/python
import netaddr

DOCUMENTATION = '''
---
module: testing_port_ip_facts
version_added: "1.1"
author: Wenda Ni (wenni@microsoft.com)
short_description: Retrive bgp peer ip facts
description:
    - Retrieve bgp peer ip for the ptf interfaces, indexed in testing_ports_id.
      The ips are to be used as the src or dst port ips in ptf-generated packets.
options:
    testing_ports_id:
        description: a sublist of ptf_interfaces.
        required: true
    dut_switch_ports:
        description: a list
        required: true
    minigraph_bgp:
        description: a list
        required: true
    minigraph_neighbors:
        description: a map
        required: true
'''

EXAMPLES = '''
Retrieve bgp peer ips
- name: Get testing port IPs
  testing_port_ip_facts:
    testing_ports_id: "{{ testing_ports_id }}"
    dut_switch_ports: "{{ dut_switch_ports }}"
    minigraph_bgp: "{{ minigraph_bgp }}"
    minigraph_neighbors: "{{ minigraph_neighbors }}"
  delegate_to: localhost
'''


def main():
    module = AnsibleModule(
        argument_spec=dict(
            testing_ports_id=dict(required=True),
            dut_switch_ports=dict(required=True),
            minigraph_bgp=dict(reguired=True),
            minigraph_neighbors=dict(reguired=True),
        ),
        supports_check_mode=True
    )

    m_args = module.params
    testing_ports_id = m_args['testing_ports_id']
    dut_switch_ports = m_args['dut_switch_ports']
    minigraph_bgp = m_args['minigraph_bgp']
    minigraph_neighbors = m_args['minigraph_neighbors']

    testing_ports_ip = {}

    for port_id in testing_ports_id:
        for peer in minigraph_bgp:
            if peer['name'] == minigraph_neighbors[dut_switch_ports[int(port_id)]]['name'] and netaddr.valid_ipv4(peer['addr']):
                testing_ports_ip[port_id] = peer['addr']
                break

    module.exit_json(ansible_facts={'testing_ports_ip': testing_ports_ip})

from ansible.module_utils.basic import *
if __name__== "__main__":
    main()

