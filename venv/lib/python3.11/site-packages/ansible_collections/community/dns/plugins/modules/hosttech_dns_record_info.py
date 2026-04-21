#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2021 Felix Fontein
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type


DOCUMENTATION = r"""
module: hosttech_dns_record_info

short_description: Retrieve records in Hosttech DNS service

version_added: 2.0.0

description:
  - Retrieves DNS records in Hosttech DNS service.
extends_documentation_fragment:
  - community.dns.hosttech
  - community.dns.hosttech.record_type_choices
  - community.dns.hosttech.record_type_seealso
  - community.dns.hosttech.zone_id_type
  - community.dns.module_record_info
  - community.dns.options.record_transformation
  - community.dns.attributes
  - community.dns.attributes.actiongroup_hosttech
  - community.dns.attributes.info_module
  - community.dns.attributes.idempotent_not_modify_state

attributes:
  action_group:
    version_added: 2.4.0

author:
  - Felix Fontein (@felixfontein)

seealso:
  - module: community.dns.hosttech_dns_record_set_info
  - plugin: community.dns.hosttech_dns_records
    plugin_type: inventory
"""

EXAMPLES = r"""
- name: Retrieve the details for the A records of new.foo.com
  community.dns.hosttech_dns_record_info:
    zone_name: foo.com
    record: new.foo.com
    type: A
    hosttech_token: access_token
  register: rec

- name: Print the A records
  ansible.builtin.debug:
    msg: "{{ rec.records }}"
"""

RETURN = r"""
records:
  description: The list of fetched records.
  type: list
  elements: dict
  returned: success and O(what) is not V(single_record)
  contains:
    record:
      description: The record name.
      type: str
      sample: sample.example.com
    prefix:
      description: The record prefix.
      type: str
      sample: sample
    type:
      description: The DNS record type.
      type: str
      sample: A
    ttl:
      description:
        - The TTL.
      type: int
      sample: 3600
    value:
      description: The DNS record's value.
      type: str
      sample: 1.2.3.4
    extra:
      description: Extra information on records.
      type: dict
      sample:
        comment: ''
  sample:
    - record: sample.example.com
      type: A
      ttl: 3600
      value: 1.2.3.4
      extra: {}

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
from ansible_collections.community.dns.plugins.module_utils.module.record_info import (
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
