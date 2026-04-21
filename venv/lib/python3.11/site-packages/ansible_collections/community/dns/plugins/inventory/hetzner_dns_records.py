# -*- coding: utf-8 -*-
#
# Copyright (c) 2021 Felix Fontein
# Copyright (c) 2020 Markus Bergholz <markuman+spambelongstogoogle@gmail.com>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations


DOCUMENTATION = r"""
name: hetzner_dns_records

short_description: Create inventory from Hetzner DNS records

version_added: 2.0.0

description:
  - This plugin allows to create an inventory from Hetzner DNS records.
  - 'For Ansible to be able to identify a YAML file as an inventory for this plugin, the inventory file must contain C(plugin:
    community.dns.hetzner_dns_records) and its filename must end with C(hetzner_dns.yaml) or C(hetzner_dns.yml).'
options:
  plugin:
    description: The name of this plugin. Should always be set to V(community.dns.hetzner_dns_records) for this plugin to
      recognize it as its own.
    required: true
    choices:
      - community.dns.hetzner_dns_records
    type: str

  filters:
    version_added: 3.0.0

extends_documentation_fragment:
  - community.dns.hetzner
  - community.dns.hetzner.plugin
  - community.dns.hetzner.record_type_choices_records_inventory
  - community.dns.hetzner.record_type_seealso
  - community.dns.hetzner.zone_id_type
  - community.dns.inventory_records
  - community.dns.options.record_transformation
  - community.library_inventory_filtering_v1.inventory_filter

notes:
  - The provider-specific O(hetzner_token) option can be templated.
author:
  - Markus Bergholz (@markuman) <markuman+spambelongstogoogle@gmail.com>
  - Felix Fontein (@felixfontein)

seealso:
  - module: community.dns.hetzner_dns_record_set_info
  - module: community.dns.hetzner_dns_record_info
"""

EXAMPLES = r"""
# filename must end with hetzner_dns.yaml or hetzner_dns.yml

plugin: community.dns.hetzner_dns_records
zone_name: domain.de
simple_filters:
  type:
    - TXT
filters:
  - include: >-
      not ansible_host.startswith('v=')
  - exclude: true
txt_transformation: unquoted

# You can also configure the token by putting secret value into this file,
# but this is discouraged. Use a lookup like below, or leave it away and
# set it with the HETZNER_DNS_TOKEN environment variable.
hetzner_token: >-
  {{ (lookup('community.sops.sops', 'keys/hetzner.sops.yml') | from_yaml).hetzner_dns_token }}
"""


from ansible_collections.community.dns.plugins.module_utils.hetzner.api import (
    create_hetzner_api,
    create_hetzner_provider_information,
)
from ansible_collections.community.dns.plugins.module_utils.http import OpenURLHelper
from ansible_collections.community.dns.plugins.plugin_utils.inventory.records import (
    RecordsInventoryModule,
)
from ansible_collections.community.dns.plugins.plugin_utils.templated_options import (
    TemplatedOptionProvider,
)


class InventoryModule(RecordsInventoryModule):
    NAME = "community.dns.hetzner_dns_records"
    VALID_ENDINGS = ("hetzner_dns.yaml", "hetzner_dns.yml")

    def setup_api(self) -> None:
        self.provider_information = create_hetzner_provider_information()
        self.api = create_hetzner_api(
            TemplatedOptionProvider(self, self.templar), OpenURLHelper()
        )
