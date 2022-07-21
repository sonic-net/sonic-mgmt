import os
import yaml

from collections import defaultdict

try:
    from ansible.module_utils.dualtor_utils import generate_mux_cable_facts
except ImportError:
    # Add parent dir for using outside Ansible
    import sys
    sys.path.append('..')
    from ansible.module_utils.dualtor_utils import generate_mux_cable_facts


def load_topo_file(topo_name):
    """Load topo definition yaml file."""
    topo_file = "vars/topo_%s.yml" % topo_name
    if not os.path.exists(topo_file):
        raise ValueError("Topo file %s not exists" % topo_file)
    with open(topo_file) as fd:
        return yaml.safe_load(fd)


class DualTorParser:

    def __init__(self, hostname, testbed_facts, host_vars, vm_config, port_alias, vlan_intfs):
        self.hostname = hostname
        self.testbed_facts = testbed_facts
        self.host_vars = host_vars
        self.vm_config = vm_config
        self.port_alias = port_alias
        self.vlan_intfs = vlan_intfs
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

        The upper ToR is always the first ToR listed in the testbed file
        '''
        self.dual_tor_facts['positions'] = {'upper': self.testbed_facts['duts'][0], 'lower': self.testbed_facts['duts'][1]}

    def parse_loopback_ips(self):
        '''
        Parses the IPv4 and IPv6 loopback IPs for the DUTs

        Similar to `parse_tor_position`, the ToR which comes first in the testbed file is always assigned the first IP
        '''

        loopback_ips = defaultdict(dict)
        addl_loopback_ips = defaultdict(dict)

        for dut_num, dut in enumerate(self.testbed_facts['duts']):
            loopback_ips[dut]['ipv4'] = self.vm_config['DUT']['loopback']['ipv4'][dut_num]
            loopback_ips[dut]['ipv6'] = self.vm_config['DUT']['loopback']['ipv6'][dut_num] 

            for loopback_num in range(1, 4): # Generate two additional loopback IPs, Loopback1, Loopback2, and Loopback3
                loopback_key = 'loopback{}'.format(loopback_num)
                loopback_dict = {}
                loopback_dict['ipv4'] = self.vm_config['DUT'][loopback_key]['ipv4'][dut_num]
                loopback_dict['ipv6'] = self.vm_config['DUT'][loopback_key]['ipv6'][dut_num]
                loopback_dict['host_ip_base_index'] = loopback_num * 2
                addl_loopback_ips[dut][loopback_num] = loopback_dict

        self.dual_tor_facts['loopback'] = loopback_ips 
        self.dual_tor_facts['addl_loopbacks'] = addl_loopback_ips

    def generate_cable_names(self):
        cables = []

        for server_num, dut_intf in enumerate(self.vlan_intfs):
            name = '{}-Servers{}-SC'.format(self.hostname, server_num)
            cable = {"hostname": name, "dut_intf": dut_intf}
            cables.append(cable)

        self.dual_tor_facts['cables'] = cables

    def generate_mux_cable_facts(self):
        topo_name = self.testbed_facts["topo"]

        topology = load_topo_file(topo_name)["topology"]
        mux_cable_facts = generate_mux_cable_facts(topology=topology)
        self.dual_tor_facts["mux_cable_facts"] = mux_cable_facts

    def get_dual_tor_facts(self):
        '''
        Gathers facts related to a dual ToR configuration
        '''
        if 'dualtor' in self.testbed_facts['topo']:
            self.parse_neighbor_tor()
            self.parse_tor_position()
            self.generate_cable_names()
            self.parse_loopback_ips()
            self.generate_mux_cable_facts()

        return self.dual_tor_facts


def main():
    module = AnsibleModule(
        argument_spec=dict(
            hostname=dict(required=True, default=None, type='str'),
            testbed_facts=dict(required=True, default=None, type='dict'),
            hostvars=dict(required=True, default=None, type='dict'),
            vm_config=dict(required=True, default=None, type='dict'),
            port_alias=dict(required=True, default=None, type='list'),
            vlan_intfs=dict(required=True, default=None, type='list')
        ),
        supports_check_mode=True
    )
    m_args = module.params
    # testbed_facts ={u'comment': u'Dual-TOR testbed', u'conf-name': u'vms-kvm-dual-t0', u'ptf_ip': u'10.250.0.109', u'ptf_netmask': u'255.255.255.0', u'ptf_ipv6': u'fec0::ffff:afa:9', u'vm_base': u'VM0108', u'server': u'server_1', u'topo': u'dualtor', u'group-name': u'vms6-4', u'ptf': u'ptf-04', u'duts_map': {u'vlab-06': 1, u'vlab-05': 0}, u'ptf_netmask_v6': u'ffff:ffff:ffff:ffff::', u'ptf_image_name': u'docker-ptf', u'duts': [u'vlab-05', u'vlab-06']}
    hostname = m_args['hostname']
    testbed_facts = m_args['testbed_facts']
    host_vars = m_args['hostvars']
    vm_config = m_args['vm_config']
    port_alias = m_args['port_alias']
    vlan_intfs = m_args['vlan_intfs']
    try:
        dual_tor_parser = DualTorParser(hostname, testbed_facts, host_vars, vm_config, port_alias, vlan_intfs)
        module.exit_json(ansible_facts={'dual_tor_facts': dual_tor_parser.get_dual_tor_facts()})
    except Exception as e:
        module.fail_json(msg=traceback.format_exc())

from ansible.module_utils.basic import *
if __name__== "__main__":
    main()
