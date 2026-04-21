# -*- coding: utf-8 -*-
#
# Copyright (c) 2021 Felix Fontein
# Copyright (c) 2020 Markus Bergholz <markuman+spambelongstogoogle@gmail.com>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations


DOCUMENTATION = r"""
name: hosttech_dns_records

short_description: Create inventory from Hosttech DNS records

version_added: 2.0.0

description:
  - This plugin allows to create an inventory from Hosttech DNS records.
  - 'For Ansible to be able to identify a YAML file as an inventory for this plugin, the inventory file must contain C(plugin:
    community.dns.hosttech_dns_records) and its filename must end with C(hosttech_dns.yaml) or C(hosttech_dns.yml).'
options:
  plugin:
    description: The name of this plugin. Should always be set to V(community.dns.hosttech_dns_records) for this plugin to
      recognize it as its own.
    required: true
    choices:
      - community.dns.hosttech_dns_records
    type: str

    # We need to overwrite zone_id to be of type string, otherwise templating cannot be passed in
  zone_id:
    type: raw
    # If there would not be ansible-base 2.10, this should be string instead. ansible-base will
    # not accept an integer for type=string options, whence type=string breaks backwards
    # compatibility with previous type=int...
    #   type: string

  filters:
    version_added: 3.0.0

extends_documentation_fragment:
  - community.dns.hosttech
  - community.dns.hosttech.plugin
  - community.dns.hosttech.record_type_choices_records_inventory
  - community.dns.hosttech.record_type_seealso
  - community.dns.hosttech.zone_id_type
  - community.dns.inventory_records
  - community.dns.options.record_transformation
  - community.library_inventory_filtering_v1.inventory_filter

notes:
  - The provider-specific O(hosttech_username), O(hosttech_password), and O(hosttech_token) options can be templated.
author:
  - Markus Bergholz (@markuman) <markuman+spambelongstogoogle@gmail.com>
  - Felix Fontein (@felixfontein)

seealso:
  - module: community.dns.hosttech_dns_record_set_info
  - module: community.dns.hosttech_dns_record_info
"""

EXAMPLES = r"""
# filename must end with hosttech_dns.yaml or hosttech_dns.yml

plugin: community.dns.hosttech_dns_records
zone_name: domain.ch
simple_filters:
  type:
    - AAAA
filters:
  - include: >-
      '*.' not in inventory_hostname
  - exclude: true

# You can also configure the token by putting secret value into this file,
# but this is discouraged. Use a lookup like below, or leave it away and
# set it with the ANSIBLE_HOSTTECH_DNS_TOKEN environment variable.
hosttech_token: >-
  {{ (lookup('community.sops.sops', 'keys/hosttech.sops.yml') | from_yaml).hosttech_dns_token }}
"""

from ansible_collections.community.dns.plugins.module_utils.hosttech.api import (
    create_hosttech_api,
    create_hosttech_provider_information,
)
from ansible_collections.community.dns.plugins.module_utils.http import OpenURLHelper
from ansible_collections.community.dns.plugins.plugin_utils.inventory.records import (
    RecordsInventoryModule,
)
from ansible_collections.community.dns.plugins.plugin_utils.templated_options import (
    TemplatedOptionProvider,
)


class InventoryModule(RecordsInventoryModule):
    NAME = "community.dns.hosttech_dns_records"
    VALID_ENDINGS = ("hosttech_dns.yaml", "hosttech_dns.yml")

    def setup_api(self) -> None:
        self.provider_information = create_hosttech_provider_information()
        self.api = create_hosttech_api(
            TemplatedOptionProvider(self, self.templar), OpenURLHelper()
        )
