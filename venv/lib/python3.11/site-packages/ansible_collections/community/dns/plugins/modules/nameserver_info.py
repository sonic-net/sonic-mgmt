#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2022, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type


DOCUMENTATION = r"""
module: nameserver_info
short_description: Look up nameservers for a DNS name
version_added: 2.6.0
description:
  - Retrieve all nameservers that are responsible for a DNS name.
extends_documentation_fragment:
  - community.dns.attributes
  - community.dns.attributes.info_module
  - community.dns.attributes.idempotent_not_modify_state
author:
  - Felix Fontein (@felixfontein)
options:
  name:
    description:
      - A list of DNS names whose nameservers to retrieve.
    required: true
    type: list
    elements: str
  resolve_addresses:
    description:
      - Whether to resolve the nameserver names to IP addresses.
    type: bool
    default: false
  query_retry:
    description:
      - Number of retries for DNS query timeouts.
    type: int
    default: 3
  query_timeout:
    description:
      - Timeout per DNS query in seconds.
    type: float
    default: 10
  always_ask_default_resolver:
    description:
      - When set to V(true) (default), will use the default resolver to find the authoritative nameservers of a subzone. See
        O(server) for how to configure the default resolver.
      - When set to V(false), will use the authoritative nameservers of the parent zone to find the authoritative nameservers
        of a subzone. This only makes sense when the nameservers were recently changed and have not yet propagated.
    type: bool
    default: true
  servfail_retries:
    description:
      - How often to retry on SERVFAIL errors.
    type: int
    default: 0
  server:
    description:
      - The DNS server(s) to use to look up the result. Must be a list of one or more IP addresses.
      - By default, the system's standard resolver is used.
    type: list
    elements: str
    version_added: 2.7.0
requirements:
  - dnspython >= 1.15.0 (maybe older versions also work)
"""

EXAMPLES = r"""
- name: Retrieve name servers of two DNS names
  community.dns.nameserver_info:
    name:
      - www.example.com
      - example.org
  register: result

- name: Show nameservers for www.example.com
  ansible.builtin.debug:
    msg: '{{ result.results[0].nameserver }}'
"""

RETURN = r"""
results:
  description:
    - Information on the nameservers for every DNS name provided in O(name).
  returned: always
  type: list
  elements: dict
  contains:
    name:
      description:
        - The DNS name this entry is for.
      returned: always
      type: str
      sample: www.example.com
    nameservers:
      description:
        - A list of nameservers for this DNS name.
      returned: success
      type: list
      elements: str
      sample:
        - ns1.example.com
        - ns2.example.com
  sample:
    - name: www.example.com
      nameservers:
        - ns1.example.com
        - ns2.example.com
    - name: example.org
      nameservers:
        - ns1.example.org
        - ns2.example.org
        - ns3.example.org
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.dns.plugins.module_utils.resolver import (
    ResolveDirectlyFromNameServers,
    assert_requirements_present,
    guarded_run,
)


def main():
    module = AnsibleModule(
        argument_spec={
            'name': {'required': True, 'type': 'list', 'elements': 'str'},
            'resolve_addresses': {'type': 'bool', 'default': False},
            'query_retry': {'type': 'int', 'default': 3},
            'query_timeout': {'type': 'float', 'default': 10},
            'always_ask_default_resolver': {'type': 'bool', 'default': True},
            'servfail_retries': {'type': 'int', 'default': 0},
            'server': {'type': 'list', 'elements': 'str'},
        },
        supports_check_mode=True,
    )
    assert_requirements_present(module)

    names = module.params['name']
    resolve_addresses = module.params['resolve_addresses']

    resolver = ResolveDirectlyFromNameServers(
        timeout=module.params['query_timeout'],
        timeout_retries=module.params['query_retry'],
        servfail_retries=module.params['servfail_retries'],
        always_ask_default_resolver=module.params['always_ask_default_resolver'],
        server_addresses=module.params['server'],
    )
    results = [None] * len(names)
    for index, name in enumerate(names):
        results[index] = {
            'name': name,
        }

    def f():
        for index, name in enumerate(names):
            results[index]['nameservers'] = sorted(resolver.resolve_nameservers(name, resolve_addresses=resolve_addresses))

    guarded_run(f, module, generate_additional_results=lambda: {'results': results})
    module.exit_json(results=results)


if __name__ == "__main__":
    main()
