#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Ansible Project
# Copyright: (c) 2021, Mark Mercado <mamercad@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = r"""
---
module: digital_ocean_cdn_endpoints_info
short_description: Display DigitalOcean CDN Endpoints
description:
  - Display DigitalOcean CDN Endpoints
author: "Mark Mercado (@mamercad)"
version_added: 1.10.0
options:
  state:
    description:
      - The usual, C(present) to create, C(absent) to destroy
    type: str
    choices: ["present", "absent"]
    default: present
extends_documentation_fragment:
  - community.digitalocean.digital_ocean.documentation
"""


EXAMPLES = r"""
- name: Display DigitalOcean CDN Endpoints
  community.digitalocean.digital_ocean_cdn_endpoints_info:
    oauth_token: "{{ lookup('ansible.builtin.env', 'DO_API_TOKEN') }}"
"""


RETURN = r"""
data:
  description: DigitalOcean CDN Endpoints
  returned: success
  type: dict
  sample:
    data:
      endpoints:
      - created_at: '2021-09-05T13:47:23Z'
        endpoint: mamercad.nyc3.cdn.digitaloceanspaces.com
        id: 01739563-3f50-4da4-a451-27f6d59d7573
        origin: mamercad.nyc3.digitaloceanspaces.com
        ttl: 3600
      meta:
        total: 1
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.digitalocean.plugins.module_utils.digital_ocean import (
    DigitalOceanHelper,
)


def run(module):
    rest = DigitalOceanHelper(module)

    endpoint = "cdn/endpoints"
    response = rest.get(endpoint)
    json_data = response.json
    status_code = response.status_code

    if status_code != 200:
        module.fail_json(
            changed=False,
            msg="Failed to get {0} information due to error [HTTP {1}: {2}]".format(
                endpoint, status_code, json_data.get("message", "(empty error message)")
            ),
        )

    module.exit_json(changed=False, data=json_data)


def main():
    argument_spec = DigitalOceanHelper.digital_ocean_argument_spec()
    argument_spec.update(state=dict(choices=["present", "absent"], default="present"))
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )
    run(module)


if __name__ == "__main__":
    main()
