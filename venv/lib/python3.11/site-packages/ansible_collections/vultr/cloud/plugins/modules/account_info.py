#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2021, René Moser <mail@renemoser.net>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: account_info
short_description: Get information about the Vultr account
description:
  - Get infos about account balance, charges and payments.
version_added: "1.0.0"
author: "René Moser (@resmo)"
extends_documentation_fragment:
  - vultr.cloud.vultr_v2
"""

EXAMPLES = """
- name: Get Vultr account infos
  vultr.cloud.account_info:
  register: result

- name: Print the infos
  ansible.builtin.debug:
    var: result.vultr_account_info
"""

RETURN = """
---
vultr_api:
  description: Response from Vultr API with a few additions/modification.
  returned: success
  type: dict
  contains:
    api_account:
      description: Account used in the ini file to select the key.
      returned: success
      type: str
      sample: default
    api_timeout:
      description: Timeout used for the API requests.
      returned: success
      type: int
      sample: 60
    api_retries:
      description: Amount of max retries for the API requests.
      returned: success
      type: int
      sample: 5
    api_retry_max_delay:
      description: Exponential backoff delay in seconds between retries up to this max delay value.
      returned: success
      type: int
      sample: 12
    api_endpoint:
      description: Endpoint used for the API requests.
      returned: success
      type: str
      sample: "https://api.vultr.com/v2"
vultr_account_info:
  description: Response from Vultr API.
  returned: success
  type: dict
  contains:
    balance:
      description: Your account balance.
      returned: success
      type: float
      sample: -214.69
    pending_charges:
      description: Charges pending.
      returned: success
      type: float
      sample: 57.03
    last_payment_date:
      description: Date of the last payment.
      returned: success
      type: str
      sample: "2021-11-07T05:57:59-05:00"
    last_payment_amount:
      description: The amount of the last payment transaction.
      returned: success
      type: float
      sample: -250.0
"""

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.vultr_v2 import AnsibleVultr, vultr_argument_spec


def main():
    argument_spec = vultr_argument_spec()

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    vultr = AnsibleVultr(
        module=module,
        namespace="vultr_account_info",
        resource_path="/account",
        ressource_result_key_singular="account",
    )

    vultr.get_result(vultr.query_by_id(resource_id=""))


if __name__ == "__main__":
    main()
