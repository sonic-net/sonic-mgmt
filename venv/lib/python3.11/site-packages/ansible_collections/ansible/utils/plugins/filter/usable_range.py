# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Filter plugin file for usable_range
"""

from __future__ import absolute_import, division, print_function

from ipaddress import IPv4Network, IPv6Network

from ansible_collections.ansible.utils.plugins.plugin_utils.base.ipaddress_utils import (
    _need_ipaddress,
    ip_network,
)
from ansible_collections.ansible.utils.plugins.plugin_utils.base.utils import _validate_args


__metaclass__ = type

DOCUMENTATION = """
    name: usable_range
    author: Priyam Sahoo (@priyamsahoo)
    version_added: "2.3.0"
    short_description: Expand the usable IP addresses
    description:
        - For a given IP address (IPv4 or IPv6) in CIDR form, the plugin generates a list of usable IP addresses belonging to the network.
    options:
        ip:
            description:
            - A string that represents an IP address of network in CIDR form
            - 'For example: C(10.0.0.0/24) or C(2001:db8:abcd:0012::0/124)'
            type: str
            required: True
    notes:
"""

EXAMPLES = r"""

#### Simple examples

- name: Expand and produce list of usable IP addresses in 10.0.0.0/28
  ansible.builtin.set_fact:
    data: "{{ '10.0.0.0/28' | ansible.utils.usable_range }}"

# TASK [Expand and produce list of usable IP addresses in 10.0.0.0/28] ************************
# ok: [localhost] => {
#     "ansible_facts": {
#         "data": {
#             "number_of_ips": 16,
#             "usable_ips": [
#                 "10.0.0.0",
#                 "10.0.0.1",
#                 "10.0.0.2",
#                 "10.0.0.3",
#                 "10.0.0.4",
#                 "10.0.0.5",
#                 "10.0.0.6",
#                 "10.0.0.7",
#                 "10.0.0.8",
#                 "10.0.0.9",
#                 "10.0.0.10",
#                 "10.0.0.11",
#                 "10.0.0.12",
#                 "10.0.0.13",
#                 "10.0.0.14",
#                 "10.0.0.15"
#             ]
#         }
#     },
#     "changed": false
# }

- name: Expand and produce list of usable IP addresses in 2001:db8:abcd:0012::0/126
  ansible.builtin.set_fact:
    data1: "{{ '2001:db8:abcd:0012::0/126' | ansible.utils.usable_range }}"

# TASK [Expand and produce list of usable IP addresses in 2001:db8:abcd:0012::0/126] ***
# ok: [localhost] => {
#     "ansible_facts": {
#         "data1": {
#             "number_of_ips": 4,
#             "usable_ips": [
#                 "2001:db8:abcd:12::",
#                 "2001:db8:abcd:12::1",
#                 "2001:db8:abcd:12::2",
#                 "2001:db8:abcd:12::3"
#             ]
#         }
#     },
#     "changed": false
# }

- name: Expand and produce list of usable IP addresses in 10.1.1.1
  ansible.builtin.set_fact:
    data: "{{ '10.1.1.1' | ansible.utils.usable_range }}"

# TASK [Expand and produce list of usable IP addresses in 10.1.1.1] ***************************
# ok: [localhost] => {
#     "ansible_facts": {
#         "data": {
#             "number_of_ips": 1,
#             "usable_ips": [
#                 "10.1.1.1"
#             ]
#         }
#     },
#     "changed": false
# }

#### Simple Use-case (looping through the list result)

- name: Expand and produce list of usable IP addresses in 127.0.0.0/28
  ansible.builtin.set_fact:
    data1: "{{ '127.0.0.0/28' | ansible.utils.usable_range }}"

- name: Ping all but first IP addresses from the generated list
  shell: "ping -c 1 {{ item }}"
  loop: "{{ data1.usable_ips[1:] }}"

# TASK [Expand and produce list of usable IP addresses in 127.0.0.0/28] ******************************
# ok: [localhost]

# TASK [Ping all but first IP addresses from the generated list] *************************************
# changed: [localhost] => (item=127.0.0.1)
# changed: [localhost] => (item=127.0.0.2)
# changed: [localhost] => (item=127.0.0.3)
# changed: [localhost] => (item=127.0.0.4)
# changed: [localhost] => (item=127.0.0.5)
# changed: [localhost] => (item=127.0.0.6)
# changed: [localhost] => (item=127.0.0.7)
# changed: [localhost] => (item=127.0.0.8)
# changed: [localhost] => (item=127.0.0.9)
# changed: [localhost] => (item=127.0.0.10)
# changed: [localhost] => (item=127.0.0.11)
# changed: [localhost] => (item=127.0.0.12)
# changed: [localhost] => (item=127.0.0.13)
# changed: [localhost] => (item=127.0.0.14)
# changed: [localhost] => (item=127.0.0.15)
"""

RETURN = """
    data:
        description:
        - Total number of usable IP addresses under the key C(number_of_ips)
        - List of usable IP addresses under the key C(usable_ips)
"""

from ansible.errors import AnsibleFilterError
from ansible.module_utils.common.text.converters import to_text
from ansible.module_utils.six import ensure_text


@_need_ipaddress
def _usable_range(ip):
    """Expand the usable IP addresses"""

    params = {"ip": ip}
    _validate_args("usable_range", DOCUMENTATION, params)

    try:
        if ip_network(ip).version == 4:
            ips = [to_text(usable_ips) for usable_ips in IPv4Network(ensure_text(ip))]
            no_of_ips = IPv4Network(ensure_text(ip)).num_addresses
        if ip_network(ip).version == 6:
            ips = [to_text(usable_ips) for usable_ips in IPv6Network(ensure_text(ip))]
            no_of_ips = IPv6Network(ensure_text(ip)).num_addresses

    except Exception as e:
        raise AnsibleFilterError(
            "Error while using plugin 'usable_range': {msg}".format(msg=to_text(e)),
        )

    return {"usable_ips": ips, "number_of_ips": no_of_ips}


class FilterModule(object):
    """usable_range"""

    def filters(self):
        """a mapping of filter names to functions"""
        return {"usable_range": _usable_range}
