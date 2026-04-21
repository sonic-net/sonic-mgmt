#!/usr/bin/python

# Copyright (c) 2022, Felix Fontein <felix@fontein.de>
# Copyright (c) 2020, Nikolay Dachev <nikolay@dachev.info>
# Copyright (c) 2018, Egor Zaitsev (@heuels)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r"""
module: api_facts
author:
  - "Egor Zaitsev (@heuels)"
  - "Nikolay Dachev (@NikolayDachev)"
  - "Felix Fontein (@felixfontein)"
version_added: 2.1.0
short_description: Collect facts from remote devices running MikroTik RouterOS using the API
description:
  - Collects a base set of device facts from a remote device that is running RouterOS. This module prepends all of the base
    network fact keys with C(ansible_net_<fact>). The facts module will always collect a base set of facts from the device
    and can enable or disable collection of additional facts.
  - As opposed to the M(community.routeros.facts) module, it uses the RouterOS API, similar to the M(community.routeros.api)
    module.
extends_documentation_fragment:
  - community.routeros.api
  - community.routeros.attributes
  - community.routeros.attributes.actiongroup_api
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
        include V(all), V(hardware), V(interfaces), and V(routing).
      - Can specify a list of values to include a larger subset. Values can also be used with an initial V(!) to specify that
        a specific subset should not be collected.
    required: false
    default:
      - all
    type: list
    elements: str
seealso:
  - module: community.routeros.facts
  - module: community.routeros.api
  - module: community.routeros.api_find_and_modify
  - module: community.routeros.api_info
  - module: community.routeros.api_modify
"""

EXAMPLES = r"""
---
- name: Collect all facts from the device
  community.routeros.api_facts:
    hostname: 192.168.88.1
    username: admin
    password: password
    gather_subset: all

- name: Do not collect hardware facts
  community.routeros.api_facts:
    hostname: 192.168.88.1
    username: admin
    password: password
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

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common.text.converters import to_native

from ansible_collections.community.routeros.plugins.module_utils.api import (
    api_argument_spec,
    check_has_library,
    create_api,
)

try:
    from librouteros.exceptions import LibRouterosError
except Exception:
    # Handled in api module_utils
    pass


class FactsBase(object):

    COMMANDS = []

    def __init__(self, module, api):
        self.module = module
        self.api = api
        self.facts = {}
        self.responses = None

    def populate(self):
        self.responses = []
        for path in self.COMMANDS:
            self.responses.append(self.query_path(path))

    def query_path(self, path):
        api_path = self.api.path()
        for part in path:
            api_path = api_path.join(part)
        try:
            return list(api_path)
        except LibRouterosError as e:
            self.module.warn('Error while querying path {path}: {error}'.format(
                path=' '.join(path),
                error=to_native(e),
            ))
            return []


class Default(FactsBase):

    COMMANDS = [
        ['system', 'identity'],
        ['system', 'resource'],
        ['system', 'routerboard'],
    ]

    def populate(self):
        super(Default, self).populate()
        data = self.responses[0]
        if data:
            self.facts['hostname'] = data[0].get('name')
        data = self.responses[1]
        if data:
            self.facts['version'] = data[0].get('version')
            self.facts['arch'] = data[0].get('architecture-name')
            self.facts['uptime'] = data[0].get('uptime')
            self.facts['cpu_load'] = data[0].get('cpu-load')
        data = self.responses[2]
        if data:
            self.facts['model'] = data[0].get('model')
            self.facts['serialnum'] = data[0].get('serial-number')


class Hardware(FactsBase):

    COMMANDS = [
        ['system', 'resource'],
    ]

    def populate(self):
        super(Hardware, self).populate()
        data = self.responses[0]
        if data:
            self.parse_filesystem_info(data[0])
            self.parse_memory_info(data[0])

    def parse_filesystem_info(self, data):
        self.facts['spacefree_mb'] = self.to_megabytes(data.get('free-hdd-space'))
        self.facts['spacetotal_mb'] = self.to_megabytes(data.get('total-hdd-space'))

    def parse_memory_info(self, data):
        self.facts['memfree_mb'] = self.to_megabytes(data.get('free-memory'))
        self.facts['memtotal_mb'] = self.to_megabytes(data.get('total-memory'))

    def to_megabytes(self, value):
        if value is None:
            return None
        return float(value) / 1024 / 1024


class Interfaces(FactsBase):

    COMMANDS = [
        ['interface'],
        ['ip', 'address'],
        ['ipv6', 'address'],
        ['ip', 'neighbor'],
    ]

    def populate(self):
        super(Interfaces, self).populate()

        self.facts['interfaces'] = {}
        self.facts['all_ipv4_addresses'] = []
        self.facts['all_ipv6_addresses'] = []
        self.facts['neighbors'] = []

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
            iface = self.facts['interfaces'].setdefault(key, (
                {"type": "ansible:unknown"} if key.startswith('*') else
                {"type": "ansible:mismatch"}))
            iface_addrs = iface.setdefault(family, [])
            addr, subnet = value['address'].split('/')
            subnet = subnet.strip()
            # Try to convert subnet to an integer
            try:
                subnet = int(subnet)
            except Exception:
                pass
            ip = dict(address=addr.strip(), subnet=subnet)
            self.add_ip_address(addr.strip(), family)
            iface_addrs.append(ip)

    def add_ip_address(self, address, family):
        if family == 'ipv4':
            self.facts['all_ipv4_addresses'].append(address)
        else:
            self.facts['all_ipv6_addresses'].append(address)

    def parse_interfaces(self, data):
        facts = {}
        for entry in data:
            if 'name' not in entry:
                continue
            entry.pop('.id', None)
            facts[entry['name']] = entry
        return facts

    def parse_detail(self, data):
        for entry in data:
            if 'interface' not in entry:
                continue
            entry.pop('.id', None)
            yield entry


class Routing(FactsBase):

    COMMANDS = [
        ['routing', 'bgp', 'peer'],
        ['routing', 'bgp', 'vpnv4-route'],
        ['routing', 'bgp', 'instance'],
        ['ip', 'route'],
        ['routing', 'ospf', 'instance'],
        ['routing', 'ospf', 'neighbor'],
    ]

    def populate(self):
        super(Routing, self).populate()
        self.facts['bgp_peer'] = {}
        self.facts['bgp_vpnv4_route'] = {}
        self.facts['bgp_instance'] = {}
        self.facts['route'] = {}
        self.facts['ospf_instance'] = {}
        self.facts['ospf_neighbor'] = {}
        data = self.responses[0]
        if data:
            peer = self.parse(data, 'name')
            self.populate_result('bgp_peer', peer)
        data = self.responses[1]
        if data:
            vpnv4 = self.parse(data, 'interface')
            self.populate_result('bgp_vpnv4_route', vpnv4)
        data = self.responses[2]
        if data:
            instance = self.parse(data, 'name')
            self.populate_result('bgp_instance', instance)
        data = self.responses[3]
        if data:
            route = self.parse(data, 'routing-mark', fallback='main')
            self.populate_result('route', route)
        data = self.responses[4]
        if data:
            instance = self.parse(data, 'name')
            self.populate_result('ospf_instance', instance)
        data = self.responses[5]
        if data:
            instance = self.parse(data, 'instance')
            self.populate_result('ospf_neighbor', instance)

    def parse(self, data, key, fallback=None):
        facts = {}
        for line in data:
            name = line.get(key) or fallback
            line.pop('.id', None)
            facts[name] = line
        return facts

    def populate_result(self, name, data):
        for key, value in data.items():
            self.facts[name][key] = value


FACT_SUBSETS = dict(
    default=Default,
    hardware=Hardware,
    interfaces=Interfaces,
    routing=Routing,
)

VALID_SUBSETS = frozenset(FACT_SUBSETS.keys())


def main():
    argument_spec = dict(
        gather_subset=dict(
            default=['all'],
            type='list',
            elements='str',
        )
    )
    argument_spec.update(api_argument_spec())

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    check_has_library(module)
    api = create_api(module)

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

    facts = {}
    facts['gather_subset'] = sorted(runable_subsets)

    instances = []
    for key in runable_subsets:
        instances.append(FACT_SUBSETS[key](module, api))

    for inst in instances:
        inst.populate()
        facts.update(inst.facts)

    ansible_facts = {}
    for key, value in facts.items():
        key = 'ansible_net_%s' % key
        ansible_facts[key] = value

    module.exit_json(ansible_facts=ansible_facts)


if __name__ == '__main__':
    main()
