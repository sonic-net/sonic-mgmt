#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2025 Markus Bergholz
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import absolute_import, division, print_function


__metaclass__ = type


DOCUMENTATION = r"""
module: adguardhome_rewrite_info

short_description: Retrieve DNS rewrite rules from AdGuardHome

version_added: 3.3.0

description:
  - Retrieves DNS rewrite rules from AdGuardHome.
extends_documentation_fragment:
  - community.dns.adguardhome.connectivity
  - community.dns.attributes
  - community.dns.attributes.info_module
  - community.dns.attributes.idempotent_not_modify_state

author:
  - Markus Bergholz (@markuman) <markuman+spambelongstogoogle@gmail.com>
"""

EXAMPLES = r"""
- name: Get DNS rewrites from AdGuardHome
  register: rewrite
  community.dns.adguardhome_rewrite_info:
    username: admin
    password: admin
    host: https://dns.osuv.de

- name: Display the rewrite rules
  debug:
    var: rewrite
"""

RETURN = r"""
rules:
  description: The list of fetched rewrite rules.
  type: list
  elements: dict
  returned: success
  contains:
    answer:
      description: Value of the rewrite.
      type: str
      sample: 192.168.178.71
    domain:
      description: Domain of the rewrite.
      type: str
      sample: dns.osuv.de
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.dns.plugins.module_utils.adguardhome.api import (
    AdGuardHomeAPIHandler,
    create_adguardhome_argument_spec,
)


def main():
    argument_spec = create_adguardhome_argument_spec()
    module = AnsibleModule(
        supports_check_mode=True,
        **argument_spec.to_kwargs()
    )

    adguardhome = AdGuardHomeAPIHandler(module.params, module.fail_json)

    result = {
        "changed": False,
        "rules": adguardhome.list()
    }

    module.exit_json(**result)


if __name__ == '__main__':
    main()
