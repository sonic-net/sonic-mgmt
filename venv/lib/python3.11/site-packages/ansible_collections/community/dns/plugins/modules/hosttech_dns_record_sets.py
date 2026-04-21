#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2017-2021 Felix Fontein
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type


DOCUMENTATION = r"""
module: hosttech_dns_record_sets

short_description: Bulk synchronize DNS record sets in Hosttech DNS service

version_added: 2.0.0

description:
  - Bulk synchronize DNS record sets in Hosttech DNS service.
  - This module replaces C(hosttech_dns_records) from community.dns before 2.0.0.
extends_documentation_fragment:
  - community.dns.hosttech
  - community.dns.hosttech.record_notes
  - community.dns.hosttech.record_type_choices_record_sets_module
  - community.dns.hosttech.record_type_seealso
  - community.dns.hosttech.zone_id_type
  - community.dns.module_record_sets
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
- name: Make sure some records exist and have the expected values
  community.dns.hosttech_dns_record_sets:
    zone_name: foo.com
    records:
      - prefix: new
        type: A
        ttl: 7200
        value:
          - 1.1.1.1
          - 2.2.2.2
      - prefix: new
        type: AAAA
        ttl: 7200
        value:
          - "::1"
      - record: foo.com
        type: TXT
        value:
          - test
    hosttech_token: access_token

- name: Synchronize DNS zone with a fixed set of records
  # If a record exists that is not mentioned here, it will be deleted
  community.dns.hosttech_dns_record_sets:
    zone_id: 23
    purge: true
    records:
      - prefix: ''
        type: A
        value: 127.0.0.1
      - prefix: ''
        type: AAAA
        value: "::1"
      - prefix: ''
        type: NS
        value:
          - ns-1.hoster.com
          - ns-2.hoster.com
          - ns-3.hoster.com
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
from ansible_collections.community.dns.plugins.module_utils.module.record_sets import (
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
