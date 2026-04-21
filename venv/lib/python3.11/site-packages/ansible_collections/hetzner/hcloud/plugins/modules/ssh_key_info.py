#!/usr/bin/python

# Copyright: (c) 2019, Hetzner Cloud GmbH <info@hetzner-cloud.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import annotations

DOCUMENTATION = """
---
module: ssh_key_info
short_description: Gather infos about your Hetzner Cloud ssh_keys.
description:
    - Gather facts about your Hetzner Cloud ssh_keys.
author:
    - Christopher Schmitt (@cschmitt-hcloud)
options:
    id:
        description:
            - The ID of the ssh key you want to get.
            - The module will fail if the provided ID is invalid.
        type: int
    name:
        description:
            - The name of the ssh key you want to get.
        type: str
    fingerprint:
        description:
            - The fingerprint of the ssh key you want to get.
        type: str
    label_selector:
        description:
            - The label selector for the ssh key you want to get.
        type: str
extends_documentation_fragment:
- hetzner.hcloud.hcloud

"""

EXAMPLES = """
- name: Gather hcloud sshkey infos
  hetzner.hcloud.ssh_key_info:
  register: output
- name: Print the gathered infos
  debug:
    var: output.hcloud_ssh_key_info
"""

RETURN = """
hcloud_ssh_key_info:
    description: The ssh key instances
    returned: Always
    type: complex
    contains:
        id:
            description: Numeric identifier of the ssh_key
            returned: always
            type: int
            sample: 1937415
        name:
            description: Name of the ssh_key
            returned: always
            type: str
            sample: my-ssh-key
        fingerprint:
            description: Fingerprint of the ssh key
            returned: always
            type: str
            sample: 0e:e0:bd:c7:2d:1f:69:49:94:44:91:f1:19:fd:35:f3
        public_key:
            description: The actual public key
            returned: always
            type: str
            sample: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGpl/tnk74nnQJxxLAtutUApUZMRJxryKh7VXkNbd4g9 john@example.com"
        labels:
            description: User-defined labels (key-value pairs)
            returned: always
            type: dict
"""

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.hcloud import AnsibleHCloud
from ..module_utils.vendor.hcloud import HCloudException
from ..module_utils.vendor.hcloud.ssh_keys import BoundSSHKey


class AnsibleHCloudSSHKeyInfo(AnsibleHCloud):
    represent = "hcloud_ssh_key_info"

    hcloud_ssh_key_info: list[BoundSSHKey] | None = None

    def _prepare_result(self):
        tmp = []

        for ssh_key in self.hcloud_ssh_key_info:
            if ssh_key is None:
                continue

            tmp.append(
                {
                    "id": ssh_key.id,
                    "name": ssh_key.name,
                    "fingerprint": ssh_key.fingerprint,
                    "public_key": ssh_key.public_key,
                    "labels": ssh_key.labels,
                }
            )
        return tmp

    def get_ssh_keys(self):
        try:
            if self.module.params.get("id") is not None:
                self.hcloud_ssh_key_info = [self.client.ssh_keys.get_by_id(self.module.params.get("id"))]
            elif self.module.params.get("name") is not None:
                self.hcloud_ssh_key_info = [self.client.ssh_keys.get_by_name(self.module.params.get("name"))]
            elif self.module.params.get("fingerprint") is not None:
                self.hcloud_ssh_key_info = [
                    self.client.ssh_keys.get_by_fingerprint(self.module.params.get("fingerprint"))
                ]
            elif self.module.params.get("label_selector") is not None:
                self.hcloud_ssh_key_info = self.client.ssh_keys.get_all(
                    label_selector=self.module.params.get("label_selector")
                )
            else:
                self.hcloud_ssh_key_info = self.client.ssh_keys.get_all()

        except HCloudException as exception:
            self.fail_json_hcloud(exception)

    @classmethod
    def define_module(cls):
        return AnsibleModule(
            argument_spec=dict(
                id={"type": "int"},
                name={"type": "str"},
                fingerprint={"type": "str"},
                label_selector={"type": "str"},
                **super().base_module_arguments(),
            ),
            supports_check_mode=True,
        )


def main():
    module = AnsibleHCloudSSHKeyInfo.define_module()
    hcloud = AnsibleHCloudSSHKeyInfo(module)

    hcloud.get_ssh_keys()
    result = hcloud.get_result()

    ansible_info = {"hcloud_ssh_key_info": result["hcloud_ssh_key_info"]}
    module.exit_json(**ansible_info)


if __name__ == "__main__":
    main()
