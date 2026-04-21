#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2021, René Moser <mail@renemoser.net>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: startup_script
short_description: Manages startup scripts on Vultr
description:
  - Create, update and remove startup scripts.
version_added: "1.0.0"
author: "René Moser (@resmo)"
options:
  name:
    description:
      - The script name.
    required: true
    type: str
  type:
    description:
      - The script type, can not be changed once created.
    default: boot
    choices: [ boot, pxe ]
    aliases: [ script_type ]
    type: str
  script:
    description:
      - The script source code.
      - Required if I(state=present).
    type: str
  state:
    description:
      - State of the script.
    default: present
    choices: [ present, absent ]
    type: str
extends_documentation_fragment:
  - vultr.cloud.vultr_v2
"""

EXAMPLES = """
- name: ensure a pxe script exists, source from a file
  vultr.cloud.startup_script:
    name: my_web_script
    script_type: pxe
    script: "{{ lookup('file', 'path/to/script') }}"

- name: ensure a boot script exists
  vultr.cloud.startup_script:
    name: vultr_startup_script
    script: "#!/bin/bash\necho Hello World > /root/hello"

- name: ensure a script is absent
  vultr.cloud.startup_script:
    name: my_web_script
    state: absent
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
vultr_startup_script:
  description: Response from Vultr API.
  returned: success
  type: dict
  contains:
    id:
      description: ID of the startup script.
      returned: success
      type: str
      sample: 7d726ffe-9be2-4f88-8cda-fa7eba1da2b5
    name:
      description: Name of the startup script.
      returned: success
      type: str
      sample: my startup script
    script:
      description: The source code of the startup script.
      returned: success
      type: str
      sample: "#!/bin/bash\necho Hello World > /root/hello"
    type:
      description: The type of the startup script.
      returned: success
      type: str
      sample: pxe
    date_created:
      description: Date the startup script was created.
      returned: success
      type: str
      sample: "2020-10-10T01:56:20+00:00"
    date_modified:
      description: Date the startup script was modified.
      returned: success
      type: str
      sample: "2020-10-10T01:56:20+00:00"
"""

import base64

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.vultr_v2 import AnsibleVultr, vultr_argument_spec


class AnsibleVultrStartupScript(AnsibleVultr):
    def configure(self):
        if self.module.params["script"]:
            self.module.params["script"] = base64.b64encode(self.module.params["script"].encode())

    def update(self, resource):
        resource["script"] = resource["script"].encode()
        return super(AnsibleVultrStartupScript, self).update(resource=resource)

    def transform_result(self, resource):
        if resource:
            resource["script"] = base64.b64decode(resource["script"]).decode()
        return resource


def main():
    argument_spec = vultr_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type="str", required=True),
            script=dict(
                type="str",
            ),
            type=dict(
                type="str",
                default="boot",
                choices=["boot", "pxe"],
                aliases=["script_type"],
            ),
            state=dict(type="str", choices=["present", "absent"], default="present"),
        )  # type: ignore
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        required_if=[
            ("state", "present", ["script"]),
        ],
        supports_check_mode=True,
    )

    vultr = AnsibleVultrStartupScript(
        module=module,
        namespace="vultr_startup_script",
        resource_path="/startup-scripts",
        ressource_result_key_singular="startup_script",
        resource_get_details=True,
        resource_create_param_keys=["name", "type", "script"],
        resource_update_param_keys=["name", "script"],
        resource_key_name="name",
    )

    if module.params.get("state") == "absent":  # type: ignore
        vultr.absent()
    else:
        vultr.present()


if __name__ == "__main__":
    main()
