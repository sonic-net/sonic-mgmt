#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Ansible Project
# Copyright: (c) 2021, Mark Mercado <mamercad@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = r"""
---
module: digital_ocean_balance_info
short_description: Display DigitalOcean customer balance
description:
  - This module can be used to display the DigitalOcean customer balance.
author: "Mark Mercado (@mamercad)"
version_added: 1.2.0
extends_documentation_fragment:
  - community.digitalocean.digital_ocean.documentation
"""


EXAMPLES = r"""
- name: Display DigitalOcean customer balance
  community.digitalocean.digital_ocean_balance_info:
    oauth_token: "{{ oauth_token }}"
"""


RETURN = r"""
# DigitalOcean API info https://docs.digitalocean.com/reference/api/api-reference/#operation/get_customer_balance
data:
    description: DigitalOcean customer balance
    returned: success
    type: dict
    sample: {
        "account_balance": "-27.52",
        "generated_at": "2021-04-11T05:08:24Z",
        "month_to_date_balance": "-27.40",
        "month_to_date_usage": "0.00"
    }
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.digitalocean.plugins.module_utils.digital_ocean import (
    DigitalOceanHelper,
)


def run(module):
    rest = DigitalOceanHelper(module)

    response = rest.get("customers/my/balance")
    if response.status_code != 200:
        module.fail_json(
            msg="Failed to fetch 'customers/my/balance' information due to error : %s"
            % response.json["message"]
        )

    module.exit_json(changed=False, data=response.json)


def main():
    argument_spec = DigitalOceanHelper.digital_ocean_argument_spec()
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    run(module)


if __name__ == "__main__":
    main()
