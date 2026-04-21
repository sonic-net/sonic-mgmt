#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2017-2021 Felix Fontein
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type


DOCUMENTATION = r"""
module: hosttech_dns_record

short_description: Add or delete a single record in Hosttech DNS service

version_added: 2.0.0

description:
  - Creates and deletes single DNS records in Hosttech DNS service.
  - This module replaces C(hosttech_dns_record) from community.dns before 2.0.0.
  - If you do not want to add/remove values, but replace values, you will be interested in modifying a B(record set) and not
    a single record. This is in particular important when working with C(CNAME) and C(SOA) records. Use the M(community.dns.hosttech_dns_record_set)
    module for working with record sets.
extends_documentation_fragment:
  - community.dns.hosttech
  - community.dns.hosttech.record_default_ttl
  - community.dns.hosttech.record_notes
  - community.dns.hosttech.record_type_choices
  - community.dns.hosttech.record_type_seealso
  - community.dns.hosttech.zone_id_type
  - community.dns.module_record
  - community.dns.options.record_transformation
  - community.dns.attributes
  - community.dns.attributes.actiongroup_hosttech

attributes:
  action_group:
    version_added: 2.4.0

author:
  - Felix Fontein (@felixfontein)
"""

EXAMPLES = r"""
- name: Add a new.foo.com A record
  community.dns.hosttech_dns_record:
    state: present
    zone: foo.com
    record: new.foo.com
    type: A
    ttl: 7200
    value: 1.1.1.1
    hosttech_token: access_token

- name: Remove a new.foo.com A record
  community.dns.hosttech_dns_record:
    state: absent
    zone_name: foo.com
    record: new.foo.com
    type: A
    ttl: 7200
    value: 2.2.2.2
    hosttech_token: access_token
"""

RETURN = r"""
zone_id:
  description: The ID of the zone.
  type: int
  returned: success
  sample: 23
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.dns.plugins.module_utils.argspec import (
    ModuleOptionProvider,
)
from ansible_collections.community.dns.plugins.module_utils.hosttech.api import (
    create_hosttech_api,
    create_hosttech_argument_spec,
    create_hosttech_provider_information,
)
from ansible_collections.community.dns.plugins.module_utils.http import ModuleHTTPHelper
from ansible_collections.community.dns.plugins.module_utils.module.record import (
    create_module_argument_spec,
    run_module,
)


def main():
    provider_information = create_hosttech_provider_information()
    argument_spec = create_hosttech_argument_spec()
    argument_spec.merge(create_module_argument_spec(provider_information=provider_information))
    module = AnsibleModule(supports_check_mode=True, **argument_spec.to_kwargs())
    run_module(module, lambda: create_hosttech_api(ModuleOptionProvider(module), ModuleHTTPHelper(module)), provider_information=provider_information)


if __name__ == '__main__':
    main()
