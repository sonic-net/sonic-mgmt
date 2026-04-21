# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Test plugin file for netaddr tests: resolvable
"""
from __future__ import absolute_import, division, print_function

import socket

from ansible_collections.ansible.utils.plugins.plugin_utils.base.ipaddress_utils import (
    _need_ipaddress,
)
from ansible_collections.ansible.utils.plugins.plugin_utils.base.utils import _validate_args


try:
    import ipaddress

    HAS_IPADDRESS = True
except ImportError:
    HAS_IPADDRESS = False

__metaclass__ = type

DOCUMENTATION = """
    name: resolvable
    author: Priyam Sahoo (@priyamsahoo)
    version_added: "2.2.0"
    short_description: Test if an IP or name can be resolved via /etc/hosts or DNS
    description:
        - This plugin checks if the provided IP address of host name can be resolved using /etc/hosts or DNS
    options:
        host:
            description:
            - A string that represents the IP address or the host name
            - 'For example: C("docs.ansible.com"), C(127.0.0.1), or C(::1)'
            type: str
            required: True
    notes:
"""

EXAMPLES = r"""

#### Simple examples

- name: Check if docs.ansible.com is resolvable or not
  ansible.builtin.set_fact:
    data: "{{ 'docs.ansible.com' is ansible.utils.resolvable }}"

# TASK [Check if docs.ansible.com is resolvable or not] **********************************
# ok: [localhost] => {
#     "ansible_facts": {
#         "data": true
#     },
#     "changed": false
# }

- name: Set host name variables
  ansible.builtin.set_fact:
    good_name: www.google.com
    bad_name: foo.google.com

- name: Assert good_name's resolvability
  assert:
    that: "{{ 'www.google.com' is ansible.utils.resolvable }}"

- name: Assert bad_name's resolvability
  assert:
    that: "{{ 'foo.google.com' is not ansible.utils.resolvable }}"

# TASK [Assert good_name's resolvability] ************************************************
# ok: [localhost] => {
#     "changed": false,
#     "msg": "All assertions passed"
# }

# TASK [Assert bad_name's resolvability] *************************************************
# ok: [localhost] => {
#     "changed": false,
#     "msg": "All assertions passed"
# }

- name: Set ip variables
  ansible.builtin.set_fact:
    ipv4_localhost: "127.0.0.1"
    ipv6_localhost: "::1"

- name: Assert ipv4_localhost's resolvability
  assert:
    that: "{{ ipv4_localhost is ansible.utils.resolvable }}"

- name: Assert ipv6_localhost's resolvability
  assert:
    that: "{{ ipv6_localhost is ansible.utils.resolvable }}"

# TASK [Assert ipv4_localhost's resolvability] *******************************************
# ok: [localhost] => {
#     "changed": false,
#     "msg": "All assertions passed"
# }

# TASK [Assert ipv6_localhost's resolvability] *******************************************
# ok: [localhost] => {
#     "changed": false,
#     "msg": "All assertions passed"
# }
"""

RETURN = """
  data:
    description:
      - If jinja test satisfies plugin expression C(true)
      - If jinja test does not satisfy plugin expression C(false)
"""


@_need_ipaddress
def _resolvable(host):
    """Test if an IP or name can be resolved via /etc/hosts or DNS"""

    params = {"host": host}
    _validate_args("resolvable", DOCUMENTATION, params)

    try:
        ipaddress.ip_address(host)
        ip = True
    except Exception:
        ip = False
    if ip:
        try:
            socket.gethostbyaddr(host)
            return True
        except Exception:
            return False
    else:
        try:
            socket.getaddrinfo(host, None)
            return True
        except Exception:
            return False


class TestModule(object):
    """network jinja tests"""

    test_map = {"resolvable": _resolvable}

    def tests(self):
        return self.test_map
