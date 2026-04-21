#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2017-2021 Felix Fontein
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type


DOCUMENTATION = r"""
module: hosttech_dns_record_set

short_description: Add or delete record sets in Hosttech DNS service

version_added: 2.0.0

description:
  - Creates and deletes DNS record sets in Hosttech DNS service.
  - This module replaces C(hosttech_dns_record) from community.dns before 2.0.0.
extends_documentation_fragment:
  - community.dns.hosttech
  - community.dns.hosttech.record_default_ttl
  - community.dns.hosttech.record_notes
  - community.dns.hosttech.record_type_choices
  - community.dns.hosttech.record_type_seealso
  - community.dns.hosttech.zone_id_type
  - community.dns.module_record_set
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
- name: Add new.foo.com as an A record with 3 IPs
  community.dns.hosttech_dns_record_set:
    state: present
    zone_name: foo.com
    record: new.foo.com
    type: A
    ttl: 7200
    value: 1.1.1.1,2.2.2.2,3.3.3.3
    hosttech_token: access_token

- name: Update new.foo.com as an A record with a list of 3 IPs
  community.dns.hosttech_dns_record_set:
    state: present
    zone_name: foo.com
    record: new.foo.com
    type: A
    ttl: 7200
    value:
      - 1.1.1.1
      - 2.2.2.2
      - 3.3.3.3
    hosttech_token: access_token

- name: Retrieve the details for new.foo.com
  community.dns.hosttech_dns_record_set_info:
    zone_name: foo.com
    record: new.foo.com
    type: A
    hosttech_username: foo
    hosttech_password: bar
  register: rec

- name: Delete new.foo.com A record using the results from the facts retrieval command
  community.dns.hosttech_dns_record_set:
    state: absent
    zone_name: foo.com
    record: "{{ rec.set.record }}"
    ttl: "{{ rec.set.ttl }}"
    type: "{{ rec.set.type }}"
    value: "{{ rec.set.value }}"
    hosttech_username: foo
    hosttech_password: bar

- name: Add an AAAA record
  # Note that because there are colons in the value that the IPv6 address must be quoted!
  community.dns.hosttech_dns_record_set:
    state: present
    zone_name: foo.com
    record: localhost.foo.com
    type: AAAA
    ttl: 7200
    value: "::1"
    hosttech_token: access_token

- name: Add a TXT record
  community.dns.hosttech_dns_record_set:
    state: present
    zone_name: foo.com
    record: localhost.foo.com
    type: TXT
    ttl: 7200
    value: 'bar'
    hosttech_username: foo
    hosttech_password: bar

- name: Remove the TXT record
  community.dns.hosttech_dns_record_set:
    state: absent
    zone_name: foo.com
    record: localhost.foo.com
    type: TXT
    ttl: 7200
    value: 'bar'
    hosttech_username: foo
    hosttech_password: bar

- name: Add a CAA record
  community.dns.hosttech_dns_record_set:
    state: present
    zone_name: foo.com
    record: foo.com
    type: CAA
    ttl: 3600
    value:
      - '128 issue "letsencrypt.org"'
      - '128 iodef "mailto:webmaster@foo.com"'
    hosttech_token: access_token

- name: Add an MX record
  community.dns.hosttech_dns_record_set:
    state: present
    zone_name: foo.com
    record: foo.com
    type: MX
    ttl: 3600
    value:
      - "10 mail.foo.com"
    hosttech_token: access_token

- name: Add a CNAME record
  community.dns.hosttech_dns_record_set:
    state: present
    zone_name: bla.foo.com
    record: foo.com
    type: CNAME
    ttl: 3600
    value:
      - foo.foo.com
    hosttech_username: foo
    hosttech_password: bar

- name: Add a PTR record
  community.dns.hosttech_dns_record_set:
    state: present
    zone_name: foo.foo.com
    record: foo.com
    type: PTR
    ttl: 3600
    value:
      - foo.foo.com
    hosttech_token: access_token

- name: Add an SPF record
  community.dns.hosttech_dns_record_set:
    state: present
    zone_name: foo.com
    record: foo.com
    type: SPF
    ttl: 3600
    value:
      - "v=spf1 a mx ~all"
    hosttech_username: foo
    hosttech_password: bar

- name: Add a PTR record
  community.dns.hosttech_dns_record_set:
    state: present
    zone_name: foo.com
    record: foo.com
    type: PTR
    ttl: 3600
    value:
      - "10 100 3333 service.foo.com"
    hosttech_token: access_token
"""

RETURN = r"""
zone_id:
  description: The ID of the zone.
  type: int
  returned: success
  sample: 23
  version_added: 0.2.0
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
from ansible_collections.community.dns.plugins.module_utils.module.record_set import (
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
