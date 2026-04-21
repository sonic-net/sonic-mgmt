#!/usr/bin/python

# Copyright (c) Ansible Project
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r"""
module: facts
author: "Egor Zaitsev (@heuels)"
short_description: Collect facts from remote devices running MikroTik RouterOS
description:
  - Collects a base set of device facts from a remote device that is running RouterOS. This module prepends all of the base
    network fact keys with C(ansible_net_<fact>). The facts module will always collect a base set of facts from the device
    and can enable or disable collection of additional facts.
extends_documentation_fragment:
  - community.routeros.attributes
  - community.routeros.attributes.facts
  - community.routeros.attributes.facts_module
  - community.routeros.attributes.idempotent_not_modify_state
attributes:
  platform:
    support: full
    platforms: RouterOS
options:
  gather_subset:
    description:
      - When supplied, this argument will restrict the facts collected to a given subset. Possible values for this argument
        include V(all), V(hardware), V(config), V(interfaces), and V(routing).
      - Can specify a list of values to include a larger subset. Values can also be used with an initial V(!) to specify that
        a specific subset should not be collected.
    required: false
    default:
      - '!config'
    type: list
    elements: str
seealso:
  - ref: ansible_collections.community.routeros.docsite.ssh-guide
    description: How to connect to RouterOS devices with SSH.
"""

EXAMPLES = r"""
---
- name: Collect all facts from the device
  community.routeros.facts:
    gather_subset: all

- name: Collect only the config and default facts
  community.routeros.facts:
    gather_subset:
      - config

- name: Do not collect hardware facts
  community.routeros.facts:
    gather_subset:
      - "!hardware"
"""

RETURN = r"""
ansible_facts:
  description: "Dictionary of IP geolocation facts for a host's IP address."
  returned: always
  type: dict
  contains:
    ansible_net_gather_subset:
      description: The list of fact subsets collected from the device.
      returned: always
      type: list

    # default
    ansible_net_model:
      description: The model name returned from the device.
      returned: O(gather_subset) contains V(default)
      type: str
    ansible_net_serialnum:
      description: The serial number of the remote device.
      returned: O(gather_subset) contains V(default)
      type: str
    ansible_net_version:
      description: The operating system version running on the remote device.
      returned: O(gather_subset) contains V(default)
      type: str
    ansible_net_hostname:
      description: The configured hostname of the device.
      returned: O(gather_subset) contains V(default)
      type: str
    ansible_net_arch:
      description: The CPU architecture of the device.
      returned: O(gather_subset) contains V(default)
      type: str
    ansible_net_uptime:
      description: The uptime of the device.
      returned: O(gather_subset) contains V(default)
      type: str
    ansible_net_cpu_load:
      description: Current CPU load.
      returned: O(gather_subset) contains V(default)
      type: str

    # hardware
    ansible_net_spacefree_mb:
      description: The available disk space on the remote device in MiB.
      returned: O(gather_subset) contains V(hardware)
      type: dict
    ansible_net_spacetotal_mb:
      description: The total disk space on the remote device in MiB.
      returned: O(gather_subset) contains V(hardware)
      type: dict
    ansible_net_memfree_mb:
      description: The available free memory on the remote device in MiB.
      returned: O(gather_subset) contains V(hardware)
      type: int
    ansible_net_memtotal_mb:
      description: The total memory on the remote device in MiB.
      returned: O(gather_subset) contains V(hardware)
      type: int

    # config
    ansible_net_config:
      description: The current active config from the device.
      returned: O(gather_subset) contains V(config)
      type: str

    ansible_net_config_nonverbose:
      description:
        - The current active config from the device in minimal form.
        - This value is idempotent in the sense that if the facts module is run twice and the device's config was not changed
          between the runs, the value is identical. This is achieved by running C(/export) and stripping the timestamp from
          the comment in the first line.
      returned: O(gather_subset) contains V(config)
      type: str
      version_added: 1.2.0

    # interfaces
    ansible_net_all_ipv4_addresses:
      description: All IPv4 addresses configured on the device.
      returned: O(gather_subset) contains V(interfaces)
      type: list
    ansible_net_all_ipv6_addresses:
      description: All IPv6 addresses configured on the device.
      returned: O(gather_subset) contains V(interfaces)
      type: list
    ansible_net_interfaces:
      description: A hash of all interfaces running on the system.
      returned: O(gather_subset) contains V(interfaces)
      type: dict
    ansible_net_neighbors:
      description: The list of neighbors from the remote device.
      returned: O(gather_subset) contains V(interfaces)
      type: dict

    # routing
    ansible_net_bgp_peer:
      description: A dictionary with BGP peer information.
      returned: O(gather_subset) contains V(routing)
      type: dict
    ansible_net_bgp_vpnv4_route:
      description: A dictionary with BGP vpnv4 route information.
      returned: O(gather_subset) contains V(routing)
      type: dict
    ansible_net_bgp_instance:
      description: A dictionary with BGP instance information.
      returned: O(gather_subset) contains V(routing)
      type: dict
    ansible_net_route:
      description: A dictionary for routes in all routing tables.
      returned: O(gather_subset) contains V(routing)
      type: dict
    ansible_net_ospf_instance:
      description: A dictionary with OSPF instances.
      returned: O(gather_subset) contains V(routing)
      type: dict
    ansible_net_ospf_neighbor:
      description: A dictionary with OSPF neighbors.
      returned: O(gather_subset) contains V(routing)
      type: dict
"""
import re

from ansible_collections.community.routeros.plugins.module_utils.routeros import run_commands
from ansible_collections.community.routeros.plugins.module_utils.routeros import routeros_argument_spec
from ansible.module_utils.basic import AnsibleModule


class FactsBase(object):

    COMMANDS = list()

    def __init__(self, module):
        self.module = module
        self.facts = dict()
        self.responses = None

    def populate(self):
        self.responses = run_commands(self.module, commands=self.COMMANDS, check_rc=False)

    def run(self, cmd):
        return run_commands(self.module, commands=cmd, check_rc=False)


class Default(FactsBase):

    COMMANDS = [
        '/system identity print without-paging',
        '/system resource print without-paging',
        '/system routerboard print without-paging'
    ]

    def populate(self):
        super(Default, self).populate()
        data = self.responses[0]
        if data:
            self.facts['hostname'] = self.parse_hostname(data)
        data = self.responses[1]
        if data:
            self.facts['version'] = self.parse_version(data)
            self.facts['arch'] = self.parse_arch(data)
            self.facts['uptime'] = self.parse_uptime(data)
            self.facts['cpu_load'] = self.parse_cpu_load(data)
        data = self.responses[2]
        if data:
            self.facts['model'] = self.parse_model(data)
            self.facts['serialnum'] = self.parse_serialnum(data)

    def parse_hostname(self, data):
        match = re.search(r'name:\s(.*)\s*$', data, re.M)
        if match:
            return match.group(1)

    def parse_version(self, data):
        match = re.search(r'version:\s(.*)\s*$', data, re.M)
        if match:
            return match.group(1)

    def parse_model(self, data):
        match = re.search(r'model:\s(.*)\s*$', data, re.M)
        if match:
            return match.group(1)

    def parse_arch(self, data):
        match = re.search(r'architecture-name:\s(.*)\s*$', data, re.M)
        if match:
            return match.group(1)

    def parse_uptime(self, data):
        match = re.search(r'uptime:\s(.*)\s*$', data, re.M)
        if match:
            return match.group(1)

    def parse_cpu_load(self, data):
        match = re.search(r'cpu-load:\s(.*)\s*$', data, re.M)
        if match:
            return match.group(1)

    def parse_serialnum(self, data):
        match = re.search(r'serial-number:\s(.*)\s*$', data, re.M)
        if match:
            return match.group(1)


class Hardware(FactsBase):

    COMMANDS = [
        '/system resource print without-paging'
    ]

    def populate(self):
        super(Hardware, self).populate()
        data = self.responses[0]
        if data:
            self.parse_filesystem_info(data)
            self.parse_memory_info(data)

    def parse_filesystem_info(self, data):
        match = re.search(r'free-hdd-space:\s(.*)([KMG]iB)', data, re.M)
        if match:
            self.facts['spacefree_mb'] = self.to_megabytes(match)
        match = re.search(r'total-hdd-space:\s(.*)([KMG]iB)', data, re.M)
        if match:
            self.facts['spacetotal_mb'] = self.to_megabytes(match)

    def parse_memory_info(self, data):
        match = re.search(r'free-memory:\s(\d+\.?\d*)([KMG]iB)', data, re.M)
        if match:
            self.facts['memfree_mb'] = self.to_megabytes(match)
        match = re.search(r'total-memory:\s(\d+\.?\d*)([KMG]iB)', data, re.M)
        if match:
            self.facts['memtotal_mb'] = self.to_megabytes(match)

    def to_megabytes(self, data):
        if data.group(2) == 'KiB':
            return float(data.group(1)) / 1024
        elif data.group(2) == 'MiB':
            return float(data.group(1))
        elif data.group(2) == 'GiB':
            return float(data.group(1)) * 1024
        else:
            return None


class Config(FactsBase):

    COMMANDS = [
        '/export verbose',
        '/export',
    ]

    RM_DATE_RE = re.compile(r'^# [a-z0-9/-][a-z0-9/-]* [0-9:]* by RouterOS')

    def populate(self):
        super(Config, self).populate()

        data = self.responses[0]
        if data:
            self.facts['config'] = data

        data = self.responses[1]
        if data:
            # remove datetime
            data = re.sub(self.RM_DATE_RE, r'# RouterOS', data)
            self.facts['config_nonverbose'] = data


class Interfaces(FactsBase):

    COMMANDS = [
        '/interface print detail without-paging',
        '/ip address print detail without-paging',
        '/ipv6 address print detail without-paging',
        '/ip neighbor print detail without-paging'
    ]

    DETAIL_RE = re.compile(r'([\w\d\-]+)=\"?(\w{3}/\d{2}/\d{4}\s\d{2}:\d{2}:\d{2}|[\w\d\-\.:/]+)')
    WRAPPED_LINE_RE = re.compile(r'^\s+(?!\d)')

    def populate(self):
        super(Interfaces, self).populate()

        self.facts['interfaces'] = dict()
        self.facts['all_ipv4_addresses'] = list()
        self.facts['all_ipv6_addresses'] = list()
        self.facts['neighbors'] = list()

        data = self.responses[0]
        if data:
            interfaces = self.parse_interfaces(data)
            self.populate_interfaces(interfaces)

        data = self.responses[1]
        if data:
            data = self.parse_detail(data)
            self.populate_addresses(data, 'ipv4')

        data = self.responses[2]
        if data:
            data = self.parse_detail(data)
            self.populate_addresses(data, 'ipv6')

        data = self.responses[3]
        if data:
            self.facts['neighbors'] = list(self.parse_detail(data))

    def populate_interfaces(self, data):
        for key, value in data.items():
            self.facts['interfaces'][key] = value

    def populate_addresses(self, data, family):
        for value in data:
            key = value['interface']
            if family not in self.facts['interfaces'][key]:
                self.facts['interfaces'][key][family] = list()
            addr, subnet = value['address'].split("/")
            ip = dict(address=addr.strip(), subnet=subnet.strip())
            self.add_ip_address(addr.strip(), family)
            self.facts['interfaces'][key][family].append(ip)

    def add_ip_address(self, address, family):
        if family == 'ipv4':
            self.facts['all_ipv4_addresses'].append(address)
        else:
            self.facts['all_ipv6_addresses'].append(address)

    def preprocess(self, data):
        preprocessed = list()
        for line in data.split('\n'):
            if len(line) == 0 or line[:5] == 'Flags':
                continue
            elif not preprocessed or not re.match(self.WRAPPED_LINE_RE, line):
                preprocessed.append(line)
            else:
                preprocessed[-1] += line
        return preprocessed

    def parse_interfaces(self, data):
        facts = dict()
        data = self.preprocess(data)
        for line in data:
            parsed = dict(re.findall(self.DETAIL_RE, line))
            if "name" not in parsed:
                continue
            facts[parsed["name"]] = dict(re.findall(self.DETAIL_RE, line))
        return facts

    def parse_detail(self, data):
        data = self.preprocess(data)
        for line in data:
            parsed = dict(re.findall(self.DETAIL_RE, line))
            if "interface" not in parsed:
                continue
            yield parsed


class Routing(FactsBase):

    COMMANDS = [
        '/routing bgp peer print detail without-paging',
        '/routing bgp vpnv4-route print detail without-paging',
        '/routing bgp instance print detail without-paging',
        '/ip route print detail without-paging',
        '/routing ospf instance print detail without-paging',
        '/routing ospf neighbor print detail without-paging'
    ]

    DETAIL_RE = re.compile(r'([\w\d\-]+)=\"?(\w{3}/\d{2}/\d{4}\s\d{2}:\d{2}:\d{2}|[\w\d\-\.:/]+)')
    WRAPPED_LINE_RE = re.compile(r'^\s+(?!\d)')

    def populate(self):
        super(Routing, self).populate()
        self.facts['bgp_peer'] = dict()
        self.facts['bgp_vpnv4_route'] = dict()
        self.facts['bgp_instance'] = dict()
        self.facts['route'] = dict()
        self.facts['ospf_instance'] = dict()
        self.facts['ospf_neighbor'] = dict()
        data = self.responses[0]
        if data:
            peer = self.parse_bgp_peer(data)
            self.populate_bgp_peer(peer)
        data = self.responses[1]
        if data:
            vpnv4 = self.parse_vpnv4_route(data)
            self.populate_vpnv4_route(vpnv4)
        data = self.responses[2]
        if data:
            instance = self.parse_instance(data)
            self.populate_bgp_instance(instance)
        data = self.responses[3]
        if data:
            route = self.parse_route(data)
            self.populate_route(route)
        data = self.responses[4]
        if data:
            instance = self.parse_instance(data)
            self.populate_ospf_instance(instance)
        data = self.responses[5]
        if data:
            instance = self.parse_ospf_neighbor(data)
            self.populate_ospf_neighbor(instance)

    def preprocess(self, data):
        preprocessed = list()
        for line in data.split('\n'):
            if len(line) == 0 or line[:5] == 'Flags':
                continue
            elif not preprocessed or not re.match(self.WRAPPED_LINE_RE, line):
                preprocessed.append(line)
            else:
                preprocessed[-1] += line
        return preprocessed

    def parse_name(self, data):
        match = re.search(r'name=.(\S+\b)', data, re.M)
        if match:
            return match.group(1)

    def parse_interface(self, data):
        match = re.search(r'interface=([\w\d\-]+)', data, re.M)
        if match:
            return match.group(1)

    def parse_instance_name(self, data):
        match = re.search(r'instance=([\w\d\-]+)', data, re.M)
        if match:
            return match.group(1)

    def parse_routing_mark(self, data):
        match = re.search(r'routing-mark=([\w\d\-]+)', data, re.M)
        if match:
            return match.group(1)
        else:
            match = 'main'
            return match

    def parse_bgp_peer(self, data):
        facts = dict()
        data = self.preprocess(data)
        for line in data:
            name = self.parse_name(line)
            facts[name] = dict()
            for (key, value) in re.findall(self.DETAIL_RE, line):
                facts[name][key] = value
        return facts

    def parse_instance(self, data):
        facts = dict()
        data = self.preprocess(data)
        for line in data:
            name = self.parse_name(line)
            facts[name] = dict()
            for (key, value) in re.findall(self.DETAIL_RE, line):
                facts[name][key] = value
        return facts

    def parse_vpnv4_route(self, data):
        facts = dict()
        data = self.preprocess(data)
        for line in data:
            name = self.parse_interface(line)
            facts[name] = dict()
            for (key, value) in re.findall(self.DETAIL_RE, line):
                facts[name][key] = value
        return facts

    def parse_route(self, data):
        facts = dict()
        data = self.preprocess(data)
        for line in data:
            name = self.parse_routing_mark(line)
            facts[name] = dict()
            for (key, value) in re.findall(self.DETAIL_RE, line):
                facts[name][key] = value
        return facts

    def parse_ospf_instance(self, data):
        facts = dict()
        data = self.preprocess(data)
        for line in data:
            name = self.parse_name(line)
            facts[name] = dict()
            for (key, value) in re.findall(self.DETAIL_RE, line):
                facts[name][key] = value
        return facts

    def parse_ospf_neighbor(self, data):
        facts = dict()
        data = self.preprocess(data)
        for line in data:
            name = self.parse_instance_name(line)
            facts[name] = dict()
            for (key, value) in re.findall(self.DETAIL_RE, line):
                facts[name][key] = value
        return facts

    def populate_bgp_peer(self, data):
        for key, value in data.items():
            self.facts['bgp_peer'][key] = value

    def populate_vpnv4_route(self, data):
        for key, value in data.items():
            self.facts['bgp_vpnv4_route'][key] = value

    def populate_bgp_instance(self, data):
        for key, value in data.items():
            self.facts['bgp_instance'][key] = value

    def populate_route(self, data):
        for key, value in data.items():
            self.facts['route'][key] = value

    def populate_ospf_instance(self, data):
        for key, value in data.items():
            self.facts['ospf_instance'][key] = value

    def populate_ospf_neighbor(self, data):
        for key, value in data.items():
            self.facts['ospf_neighbor'][key] = value


FACT_SUBSETS = dict(
    default=Default,
    hardware=Hardware,
    interfaces=Interfaces,
    config=Config,
    routing=Routing,
)

VALID_SUBSETS = frozenset(FACT_SUBSETS.keys())


def main():
    """main entry point for module execution
    """
    argument_spec = dict(
        gather_subset=dict(default=['!config'], type='list', elements='str')
    )

    argument_spec.update(routeros_argument_spec)

    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True)

    gather_subset = module.params['gather_subset']

    runable_subsets = set()
    exclude_subsets = set()

    for subset in gather_subset:
        if subset == 'all':
            runable_subsets.update(VALID_SUBSETS)
            continue

        if subset.startswith('!'):
            subset = subset[1:]
            if subset == 'all':
                exclude_subsets.update(VALID_SUBSETS)
                continue
            exclude = True
        else:
            exclude = False

        if subset not in VALID_SUBSETS:
            module.fail_json(msg='Bad subset: %s' % subset)

        if exclude:
            exclude_subsets.add(subset)
        else:
            runable_subsets.add(subset)

    if not runable_subsets:
        runable_subsets.update(VALID_SUBSETS)

    runable_subsets.difference_update(exclude_subsets)
    runable_subsets.add('default')

    facts = dict()
    facts['gather_subset'] = list(runable_subsets)

    instances = list()
    for key in runable_subsets:
        instances.append(FACT_SUBSETS[key](module))

    for inst in instances:
        inst.populate()
        facts.update(inst.facts)

    ansible_facts = dict()
    for key, value in facts.items():
        key = 'ansible_net_%s' % key
        ansible_facts[key] = value

    module.exit_json(ansible_facts=ansible_facts)


if __name__ == '__main__':
    main()
