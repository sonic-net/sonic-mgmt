#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2021 Felix Fontein
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type


DOCUMENTATION = r"""
module: hetzner_dns_record_info

short_description: Retrieve records in Hetzner DNS service

version_added: 2.0.0

description:
  - Retrieves DNS records in Hetzner DNS service.
extends_documentation_fragment:
  - community.dns.hetzner
  - community.dns.hetzner.record_type_choices
  - community.dns.hetzner.record_type_seealso
  - community.dns.hetzner.zone_id_type
  - community.dns.module_record_info
  - community.dns.options.record_transformation
  - community.dns.attributes
  - community.dns.attributes.actiongroup_hetzner
  - community.dns.attributes.info_module
  - community.dns.attributes.idempotent_not_modify_state

attributes:
  action_group:
    version_added: 2.4.0

author:
  - Markus Bergholz (@markuman) <markuman+spambelongstogoogle@gmail.com>
  - Felix Fontein (@felixfontein)

seealso:
  - module: community.dns.hetzner_dns_record_set_info
  - plugin: community.dns.hetzner_dns_records
    plugin_type: inventory
"""

EXAMPLES = r"""
- name: Retrieve the details for the A records of new.foo.com
  community.dns.hetzner_dns_record_info:
    zone: foo.com
    record: new.foo.com
    type: A
    hetzner_token: access_token
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
        - Will return V(none) if the zone's default TTL is used.
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
        created: '2021-07-09T11:18:37Z'
        modified: '2021-07-09T11:18:37Z'
  sample:
    - record: sample.example.com
      type: A
      ttl: 3600
      value: 1.2.3.4
      extra: {}

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
from ansible_collections.community.dns.plugins.module_utils.module.record_info import (
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
