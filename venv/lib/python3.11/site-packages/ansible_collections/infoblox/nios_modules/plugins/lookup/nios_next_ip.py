# Copyright (c) 2018-2019 Red Hat, Inc.
# Copyright (c) 2020 Infoblox, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = '''
---
name: nios_next_ip
short_description: Return the next available IP address for a network
version_added: "1.0.0"
description:
  - Uses the Infoblox WAPI API to return the next available IP addresses
    for a given network CIDR
requirements:
  - infoblox-client

options:
    _terms:
      description: The CIDR network to retrieve the next address(es) from.
      required: True
      type: str
    use_range:
      description: Use DHCP range to retrieve the next available IP address(es). Requested number of IP Addresses must be between 1 and 20.
      required: false
      default: false
      type: bool
    num:
      description: The number of IP address(es) to return.
      required: false
      default: 1
      type: int
    exclude:
      description: List of IP's that need to be excluded from returned IP addresses.
      required: false
      type: list
      elements: str
    network_view:
      description: The network view to retrieve the CIDR network from.
      required: false
      default: default
      type: str
'''

EXAMPLES = """
- name: return next available IP address for network 192.168.10.0/24
  ansible.builtin.set_fact:
    ipaddr: "{{ lookup('infoblox.nios_modules.nios_next_ip', '192.168.10.0/24',
    provider={'host': 'nios01', 'username': 'admin', 'password': 'password'}) }}"

- name: return next available IP address for network 192.168.10.0/24 from DHCP range
  ansible.builtin.set_fact:
    ipaddr: "{{ lookup('infoblox.nios_modules.nios_next_ip', '192.168.10.0/24',
    use_range=true, provider={'host': 'nios01', 'username': 'admin', 'password': 'password'}) }}"

- name: return next available IP address for network 192.168.10.0/24 in a non-default network view
  ansible.builtin.set_fact:
    ipaddr: "{{ lookup('infoblox.nios_modules.nios_next_ip', '192.168.10.0/24', network_view='ansible',
                provider={'host': 'nios01', 'username': 'admin', 'password': 'password'}) }}"

- name: return the next 3 available IP addresses for network 192.168.10.0/24
  ansible.builtin.set_fact:
    ipaddr: "{{ lookup('infoblox.nios_modules.nios_next_ip', '192.168.10.0/24', num=3,
                       provider={'host': 'nios01', 'username': 'admin', 'password': 'password'}) }}"

- name: return the next 3 available IP addresses for network 192.168.10.0/24
        excluding ip addresses - ['192.168.10.1', '192.168.10.2']
  ansible.builtin.set_fact:
    ipaddr: "{{ lookup('infoblox.nios_modules.nios_next_ip', '192.168.10.0/24', num=3,
                exclude=['192.168.10.1', '192.168.10.2'],
                provider={'host': 'nios01', 'username': 'admin', 'password': 'password'}) }}"

- name: return next available IP address for network fd30:f52:2:12::/64
  ansible.builtin.set_fact:
    ipaddr: "{{ lookup('infoblox.nios_modules.nios_next_ip', 'fd30:f52:2:12::/64',
    provider={'host': 'nios01', 'username': 'admin', 'password': 'password'}) }}"
"""

RETURN = """
_list:
  description:
    - The list of next IP addresses available
  returned: always
  type: list
"""

from ansible.plugins.lookup import LookupBase
from ansible.errors import AnsibleError
from ..module_utils.api import WapiLookup
import ipaddress


class LookupModule(LookupBase):

    def run(self, terms, variables=None, **kwargs):
        try:
            network = terms[0]
        except IndexError:
            raise AnsibleError('missing argument in the form of A.B.C.D/E')

        provider = kwargs.pop('provider', {})
        wapi = WapiLookup(provider)
        network_view = kwargs.get('network_view', 'default')

        if isinstance(ipaddress.ip_network(network), ipaddress.IPv6Network):
            object_type = 'ipv6range' if kwargs.get('use_range', False) else 'ipv6network'
        else:
            object_type = 'range' if kwargs.get('use_range', False) else 'network'

        network_obj = wapi.get_object(object_type, {'network': network, 'network_view': network_view})

        if network_obj is None:
            raise AnsibleError('unable to find network object %s' % network)

        num = kwargs.get('num', 1)
        exclude_ip = kwargs.get('exclude', [])

        ref_list = [network['_ref'] for network in network_obj if network['network_view'] == network_view]
        if not ref_list:
            raise AnsibleError('no records found')

        for ref in ref_list:
            try:
                avail_ips = wapi.call_func('next_available_ip', ref, {'num': num, 'exclude': exclude_ip})
                if len(avail_ips['ips']) >= num:
                    return [avail_ips['ips']]
            except Exception:
                continue

        raise AnsibleError('unable to find the required number of IPs')
