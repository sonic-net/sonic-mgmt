#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2021 Felix Fontein
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type


DOCUMENTATION = r"""
module: hetzner_dns_record_set

short_description: Add or delete record sets in Hetzner DNS service

version_added: 2.0.0

description:
  - Creates and deletes DNS record sets in Hetzner DNS service.
extends_documentation_fragment:
  - community.dns.hetzner
  - community.dns.hetzner.record_default_ttl
  - community.dns.hetzner.record_notes
  - community.dns.hetzner.record_type_choices
  - community.dns.hetzner.record_type_seealso
  - community.dns.hetzner.zone_id_type
  - community.dns.module_record_set
  - community.dns.options.bulk_operations
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
- name: Add new.foo.com as an A record with 3 IPs
  community.dns.hetzner_dns_record_set:
    state: present
    zone: foo.com
    record: new.foo.com
    type: A
    ttl: 7200
    value: 1.1.1.1,2.2.2.2,3.3.3.3
    hetzner_token: access_token

- name: Update new.foo.com as an A record with a list of 3 IPs
  community.dns.hetzner_dns_record_set:
    state: present
    zone: foo.com
    record: new.foo.com
    type: A
    ttl: 7200
    value:
      - 1.1.1.1
      - 2.2.2.2
      - 3.3.3.3
    hetzner_token: access_token

- name: Retrieve the details for new.foo.com
  community.dns.hetzner_dns_record_set_info:
    zone: foo.com
    record: new.foo.com
    type: A
    hetzner_token: access_token
  register: rec

- name: Delete new.foo.com A record using the results from the facts retrieval command
  community.dns.hetzner_dns_record_set:
    state: absent
    zone: foo.com
    record: "{{ rec.set.record }}"
    ttl: "{{ rec.set.ttl }}"
    type: "{{ rec.set.type }}"
    value: "{{ rec.set.value }}"
    hetzner_token: access_token

- name: Add an AAAA record
  # Note that because there are colons in the value that the IPv6 address must be quoted!
  community.dns.hetzner_dns_record_set:
    state: present
    zone: foo.com
    record: localhost.foo.com
    type: AAAA
    ttl: 7200
    value: "::1"
    hetzner_token: access_token

- name: Add a TXT record
  community.dns.hetzner_dns_record_set:
    state: present
    zone: foo.com
    record: localhost.foo.com
    type: TXT
    ttl: 7200
    value: 'bar'
    hetzner_token: access_token

- name: Remove the TXT record
  community.dns.hetzner_dns_record_set:
    state: absent
    zone: foo.com
    record: localhost.foo.com
    type: TXT
    ttl: 7200
    value: 'bar'
    hetzner_token: access_token

- name: Add a CAA record
  community.dns.hetzner_dns_record_set:
    state: present
    zone: foo.com
    record: foo.com
    type: CAA
    value:
      - '128 issue "letsencrypt.org"'
      - '128 iodef "mailto:webmaster@foo.com"'
    hetzner_token: access_token

- name: Add an MX record
  community.dns.hetzner_dns_record_set:
    state: present
    zone: foo.com
    record: foo.com
    type: MX
    ttl: 3600
    value:
      - "10 mail.foo.com"
    hetzner_token: access_token

- name: Add a CNAME record
  community.dns.hetzner_dns_record_set:
    state: present
    zone: bla.foo.com
    record: foo.com
    type: CNAME
    ttl: 3600
    value:
      - foo.foo.com
    hetzner_token: access_token

- name: Add a PTR record
  community.dns.hetzner_dns_record_set:
    state: present
    zone: foo.foo.com
    record: foo.com
    type: PTR
    ttl: 3600
    value:
      - foo.foo.com
    hetzner_token: access_token

- name: Add an SPF record
  community.dns.hetzner_dns_record_set:
    state: present
    zone: foo.com
    record: foo.com
    type: SPF
    ttl: 3600
    value:
      - "v=spf1 a mx ~all"
    hetzner_token: access_token

- name: Add a PTR record
  community.dns.hetzner_dns_record_set:
    state: present
    zone: foo.com
    record: foo.com
    type: PTR
    ttl: 3600
    value:
      - "10 100 3333 service.foo.com"
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
from ansible_collections.community.dns.plugins.module_utils.module.record_set import (
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
