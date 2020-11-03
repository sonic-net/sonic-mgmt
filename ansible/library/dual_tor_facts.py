import os
import yaml

class DualTorParser:

    def __init__(self, hostname, testbed_facts, host_vars):
        self.hostname = hostname
        self.testbed_facts = testbed_facts
        self.host_vars= host_vars

    def parse_neighbor_tor(self):
        '''
        Parses information about the other ToR in a dual ToR pair
        '''
        neighbor = {}
        neighbor['hostname'] = [dut for dut in self.testbed_facts['duts'] if dut != self.hostname][0]
        neighbor['ip'] = self.host_vars[neighbor['hostname']]['ansible_host']
        neighbor['hwsku'] = self.host_vars[neighbor['hostname']]['hwsku']

        return neighbor

    def get_tor_position(self):
        '''
        Determines the position ('U' for upper and 'L' for lower) of the ToR.

        The upper ToR is always the first ToR alphabetically by hostname
        '''
        upper_tor, lower_tor = sorted(self.testbed_facts['duts'])
        return {'upper': upper_tor, 'lower': lower_tor}
        
    def get_v_links(self):
        pass

    def get_y_links(self):
        pass

    def get_link_meta(self):
        pass

    def parse_dual_tor_facts(self):
        '''
        Gathers facts related to a dual ToR configuration
        '''
        dual_tor_facts = {}

        if self.testbed_facts['topo'] == 'dualtor':
            dual_tor_facts['neighbor'] = self.parse_neighbor_tor()
            dual_tor_facts['positions'] = self.get_tor_position()
            dual_tor_facts['v_links'] = self.get_v_links()
            dual_tor_facts['y_links'] = self.get_y_links()
            dual_tor_facts['link_meta'] = self.get_link_meta()

        return dual_tor_facts


def main():
    module = AnsibleModule(
        argument_spec=dict(
            hostname=dict(required=True, default=None, type='str'),
            testbed_facts=dict(required=True, default=None, type='dict'),
            hostvars=dict(required=True, default=None, type='dict')
        ),
        supports_check_mode=True
    )
    m_args = module.params
    # testbed_facts ={u'comment': u'Dual-TOR testbed', u'conf-name': u'vms-kvm-dual-t0', u'ptf_ip': u'10.250.0.109', u'ptf_netmask': u'255.255.255.0', u'ptf_ipv6': u'fec0::ffff:afa:9', u'vm_base': u'VM0108', u'server': u'server_1', u'topo': u'dualtor', u'group-name': u'vms6-4', u'ptf': u'ptf-04', u'duts_map': {u'vlab-06': 1, u'vlab-05': 0}, u'ptf_netmask_v6': u'ffff:ffff:ffff:ffff::', u'ptf_image_name': u'docker-ptf', u'duts': [u'vlab-05', u'vlab-06']}
    hostname = m_args['hostname']
    testbed_facts = m_args['testbed_facts']
    host_vars= m_args['hostvars']
    try:
        dual_tor_parser = DualTorParser(hostname, testbed_facts, host_vars)
        module.exit_json(ansible_facts={'dual_tor_facts': dual_tor_parser.parse_dual_tor_facts()})
    except Exception as e:
        module.fail_json(msg=traceback.format_exc())

from ansible.module_utils.basic import *
if __name__== "__main__":
    main()
