from collections import defaultdict
class DualTorParser:

    def __init__(self, hostname, testbed_facts, host_vars, vm_config):
        self.hostname = hostname
        self.testbed_facts = testbed_facts
        self.host_vars = host_vars
        self.vm_config = vm_config
        self.dual_tor_facts = {}

    def parse_neighbor_tor(self):
        '''
        Parses information about the other ToR in a dual ToR pair
        '''
        neighbor = {}
        neighbor['hostname'] = [dut for dut in self.testbed_facts['duts'] if dut != self.hostname][0]
        neighbor['ip'] = self.host_vars[neighbor['hostname']]['ansible_host']
        neighbor['hwsku'] = self.host_vars[neighbor['hostname']]['hwsku']

        self.dual_tor_facts['neighbor'] = neighbor

    def parse_tor_position(self):
        '''
        Determines the position ('U' for upper and 'L' for lower) of the ToR.

        The upper ToR is always the first ToR alphabetically by hostname
        '''
        upper_tor, lower_tor = sorted(self.testbed_facts['duts'])
        self.dual_tor_facts['positions'] = {'upper': upper_tor, 'lower': lower_tor}

    def parse_loopback_ips(self):
        '''
        Parses the IPv4 and IPv6 loopback IPs for the DUTs

        Similar to `parse_tor_position`, the ToR which comes first alphabetically is always assigned the first IP
        '''

        loopback_ips = defaultdict(dict)

        ipv4_loopbacks = sorted(self.vm_config['DUT']['loopback']['ipv4'])
        ipv6_loopbacks = sorted(self.vm_config['DUT']['loopback']['ipv6'])

        for i, dut in enumerate(sorted(self.testbed_facts['duts'])):
            loopback_ips[dut]['ipv4'] = ipv4_loopbacks[i]
            loopback_ips[dut]['ipv6'] = ipv6_loopbacks[i] 

        self.dual_tor_facts['loopback'] = loopback_ips     

    def generate_cable_names(self):
        cables = []

        for vm in sorted(self.vm_config['vm'].keys()):
            name = '{}-{}-SC'.format(self.hostname, vm)
            cables.append(name)

        self.dual_tor_facts['cables'] = cables

    def get_dual_tor_facts(self):
        '''
        Gathers facts related to a dual ToR configuration
        '''
        if 'dualtor' in self.testbed_facts['topo']:
            self.parse_neighbor_tor()
            self.parse_tor_position()
            self.generate_cable_names()
            self.parse_loopback_ips()

        return self.dual_tor_facts


def main():
    module = AnsibleModule(
        argument_spec=dict(
            hostname=dict(required=True, default=None, type='str'),
            testbed_facts=dict(required=True, default=None, type='dict'),
            hostvars=dict(required=True, default=None, type='dict'),
            vm_config=dict(required=True, default=None, type='dict')
        ),
        supports_check_mode=True
    )
    m_args = module.params
    # testbed_facts ={u'comment': u'Dual-TOR testbed', u'conf-name': u'vms-kvm-dual-t0', u'ptf_ip': u'10.250.0.109', u'ptf_netmask': u'255.255.255.0', u'ptf_ipv6': u'fec0::ffff:afa:9', u'vm_base': u'VM0108', u'server': u'server_1', u'topo': u'dualtor', u'group-name': u'vms6-4', u'ptf': u'ptf-04', u'duts_map': {u'vlab-06': 1, u'vlab-05': 0}, u'ptf_netmask_v6': u'ffff:ffff:ffff:ffff::', u'ptf_image_name': u'docker-ptf', u'duts': [u'vlab-05', u'vlab-06']}
    hostname = m_args['hostname']
    testbed_facts = m_args['testbed_facts']
    host_vars = m_args['hostvars']
    vm_config = m_args['vm_config']
    try:
        dual_tor_parser = DualTorParser(hostname, testbed_facts, host_vars, vm_config)
        module.exit_json(ansible_facts={'dual_tor_facts': dual_tor_parser.get_dual_tor_facts()})
    except Exception as e:
        module.fail_json(msg=traceback.format_exc())

from ansible.module_utils.basic import *
if __name__== "__main__":
    main()
