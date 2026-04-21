#!/usr/bin/python
#
# Copyright (c) 2018, Yanis Guenane <yanis+ansible@guenane.org>
# Copyright (c) 2021, René Moser <mail@renemoser.net>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: dns_domain_info
short_description: Gather information about the Vultr DNS domains
description:
  - Gather information about DNS domains available.
version_added: "1.0.0"
author:
  - "Yanis Guenane (@Spredzy)"
  - "René Moser (@resmo)"
extends_documentation_fragment:
  - vultr.cloud.vultr_v2
"""

EXAMPLES = """
- name: Gather Vultr DNS domains information
  vultr.cloud.dns_domain_info:
  register: result

- name: Print the gathered information
  ansible.builtin.debug:
    var: result.vultr_dns_domain_info
"""

RETURN = """
---
vultr_api:
  description: Response from Vultr API with a few additions/modification.
  returned: success
  type: dict
  contains:
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
vultr_dns_domain_info:
  description: Response from Vultr API as list.
  returned: success
  type: list
  contains:
    domain:
      description: Name of the DNS Domain.
      returned: success
      type: str
      sample: example.com
    dns_sec:
      description: Whether DNSSEC is enabled or disabled.
      returned: success
      type: str
      sample: disabled
    date_created:
      description: Date the DNS domain was created.
      returned: success
      type: str
      sample: "2020-10-10T01:56:20+00:00"
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
        namespace="vultr_dns_domain_info",
        resource_path="/domains",
        ressource_result_key_singular="domain",
    )

    vultr.get_result(vultr.query_list())


if __name__ == "__main__":
    main()
