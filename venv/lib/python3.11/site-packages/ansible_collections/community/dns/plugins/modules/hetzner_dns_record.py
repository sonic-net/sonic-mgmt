#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2021 Felix Fontein
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type


DOCUMENTATION = r"""
module: hetzner_dns_record

short_description: Add or delete a single record in Hetzner DNS service

version_added: 2.0.0

description:
  - Creates and deletes single DNS records in Hetzner DNS service.
  - If you do not want to add/remove values, but replace values, you will be interested in modifying a B(record set) and not
    a single record. This is in particular important when working with C(CNAME) and C(SOA) records. Use the M(community.dns.hetzner_dns_record_set)
    module for working with record sets.
extends_documentation_fragment:
  - community.dns.hetzner
  - community.dns.hetzner.record_default_ttl
  - community.dns.hetzner.record_notes
  - community.dns.hetzner.record_type_choices
  - community.dns.hetzner.record_type_seealso
  - community.dns.hetzner.zone_id_type
  - community.dns.module_record
  - community.dns.options.record_transformation
  - community.dns.attributes
  - community.dns.attributes.actiongroup_hetzner

attributes:
  action_group:
    version_added: 2.4.0

author:
  - Markus Bergholz (@markuman) <markuman+spambelongstogoogle@gmail.com>
  - Felix Fontein (@felixfontein)
"""

EXAMPLES = r"""
- name: Add a new.foo.com A record
  community.dns.hetzner_dns_record:
    state: present
    zone: foo.com
    record: new.foo.com
    type: A
    ttl: 7200
    value: 1.1.1.1
    hetzner_token: access_token

- name: Add A record using prefix for www.example.com
  community.dns.hetzner_dns_record:
    state: present
    zone_name: example.com
    prefix: www
    type: A
    value: 198.51.100.25
    hetzner_token: "{{ lookup('env', 'HETZNER_DNS_TOKEN') }}"

- name: Remove a new.foo.com A record
  community.dns.hetzner_dns_record:
    state: absent
    zone_name: foo.com
    record: new.foo.com
    type: A
    ttl: 7200
    value: 2.2.2.2
    hetzner_token: access_token
"""

RETURN = r"""
zone_id:
  description: The ID of the zone.
  type: str
  returned: success
  sample: 23
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.dns.plugins.module_utils.argspec import (
    ModuleOptionProvider,
)
from ansible_collections.community.dns.plugins.module_utils.hetzner.api import (
    create_hetzner_api,
    create_hetzner_argument_spec,
    create_hetzner_provider_information,
)
from ansible_collections.community.dns.plugins.module_utils.http import ModuleHTTPHelper
from ansible_collections.community.dns.plugins.module_utils.module.record import (
    create_module_argument_spec,
    run_module,
)


def main():
    provider_information = create_hetzner_provider_information()
    argument_spec = create_hetzner_argument_spec()
    argument_spec.merge(create_module_argument_spec(provider_information=provider_information))
    module = AnsibleModule(supports_check_mode=True, **argument_spec.to_kwargs())
    run_module(module, lambda: create_hetzner_api(ModuleOptionProvider(module), ModuleHTTPHelper(module)), provider_information=provider_information)


if __name__ == '__main__':
    main()
