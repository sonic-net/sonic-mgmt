# Copyright (c) 2018-2019 Red Hat, Inc.
# Copyright (c) 2020 Infoblox, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = '''
---
name: nios_next_network
short_description: Return the next available network range for a network-container
version_added: "1.0.0"
description:
  - Uses the Infoblox WAPI API to return the next available network addresses for
    a given network CIDR
requirements:
  - infoblox_client

options:
    _terms:
      description: The CIDR network to retrieve the next network from next available network within the specified
                   container.
      required: True
      type: str
    cidr:
      description:
        - The CIDR of the network to retrieve the next network from next available network within the
          specified container. Also, Requested CIDR must be specified and greater than the parent CIDR.
      required: True
      type: str
    num:
      description: The number of network addresses to return from network-container.
      required: false
      default: 1
      type: int
    exclude:
      description: Network addresses returned from network-container excluding list of user's input network range.
      required: false
      default: ''
      type: list
      elements: str
    network_view:
      description: The network view to retrieve the CIDR network from.
      required: false
      default: default
      type: str
'''

EXAMPLES = """
- name: return next available network for network-container 192.168.10.0/24
  ansible.builtin.set_fact:
    networkaddr: "{{ lookup('infoblox.nios_modules.nios_next_network', '192.168.10.0/24', cidr=25,
                        provider={'host': 'nios01', 'username': 'admin', 'password': 'password'}) }}"

- name: return next available network for network-container 192.168.10.0/24 in a non-default network view
  ansible.builtin.set_fact:
    networkaddr: "{{ lookup('infoblox.nios_modules.nios_next_network', '192.168.10.0/24', cidr=25, network_view='ansible'
                        provider={'host': 'nios01', 'username': 'admin', 'password': 'password'}) }}"

- name: return the next 2 available network addresses for network-container 192.168.10.0/24
  ansible.builtin.set_fact:
    networkaddr: "{{ lookup('infoblox.nios_modules.nios_next_network', '192.168.10.0/24', cidr=25, num=2,
                        provider={'host': 'nios01', 'username': 'admin', 'password': 'password'}) }}"

- name: return the available network addresses for network-container 192.168.10.0/24 excluding network range '192.168.10.0/25'
  ansible.builtin.set_fact:
    networkaddr: "{{ lookup('infoblox.nios_modules.nios_next_network', '192.168.10.0/24', cidr=25, exclude=['192.168.10.0/25'],
                        provider={'host': 'nios01', 'username': 'admin', 'password': 'password'}) }}"

- name: return the available ipv6 network addresses for network-container 2001:1:111:1::0/64
  set_fact:
    networkaddr: "{{ lookup('infoblox.nios_modules.nios_next_network', '2001:1:111:1::0/64', cidr=126,
                        provider={'host': 'nios01', 'username': 'admin', 'password': 'password'}) }}"
"""

RETURN = """
_list:
  description:
    - The list of next network addresses available
  returned: always
  type: list
"""

from ansible.plugins.lookup import LookupBase
from ansible.module_utils._text import to_text
from ansible.errors import AnsibleError
from ..module_utils.api import WapiLookup
from ..module_utils.api import NIOS_IPV4_NETWORK_CONTAINER, NIOS_IPV6_NETWORK_CONTAINER
import ipaddress


class LookupModule(LookupBase):

    def run(self, terms, variables=None, **kwargs):
        try:
            network = ipaddress.ip_network(terms[0], strict=True)
        except IndexError:
            raise AnsibleError('network argument is missing')
        except (ValueError, TypeError) as error:
            raise AnsibleError('network argument is invalid %s' % error)
        try:
            cidr = kwargs.get('cidr', 24)
            # maybe using network.prefixlen+1 as default
        except IndexError:
            raise AnsibleError('missing CIDR argument in the form of xx')

        if network.prefixlen >= cidr:
            raise AnsibleError('cidr %s must be greater than parent network cidr %s' % (cidr, network.prefixlen))

        container_type = None
        network_objects = None

        # check for ip version 4 or 6 else die
        if network.version == 4:
            container_type = NIOS_IPV4_NETWORK_CONTAINER
            if cidr not in range(1, 32):
                raise AnsibleError('cidr %s must be in range 1 to 32' % cidr)
        elif network.version == 6:
            container_type = NIOS_IPV6_NETWORK_CONTAINER
            if cidr not in range(1, 128):
                raise AnsibleError('cidr %s must be in range 1 to 128' % cidr)
        else:
            raise AnsibleError('not a valid ipv4 or ipv6 network definition %s' % terms[0])

        # check for valid subnetting cidr
        if network.prefixlen >= cidr:
            raise AnsibleError('cidr %s must be greater than parent network cidr %s' % (cidr, network.prefixlen))

        provider = kwargs.pop('provider', {})
        wapi = WapiLookup(provider)

        if container_type is None:
            raise AnsibleError('unable to identify network-container type')

        network_objects = wapi.get_object(container_type, {'network': network.with_prefixlen})

        if network_objects is None:
            raise AnsibleError('unable to find network-container object %s' % network.with_prefixlen)

        num = kwargs.get('num', 1)
        exclude_ip = kwargs.get('exclude', [])
        network_view = kwargs.get('network_view', 'default')

        try:
            ref_list = [network_obj['_ref'] for network_obj in network_objects if network_obj['network_view'] == network_view]
            if not ref_list:
                raise AnsibleError('no records found')
            else:
                ref = ref_list[0]
            avail_nets = wapi.call_func('next_available_network', ref, {'cidr': cidr, 'num': num, 'exclude': exclude_ip})
            return [avail_nets['networks']]
        except Exception as exc:
            raise AnsibleError(to_text(exc))
