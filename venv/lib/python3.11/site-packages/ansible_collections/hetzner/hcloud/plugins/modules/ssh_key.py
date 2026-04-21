#!/usr/bin/python

# Copyright: (c) 2019, Hetzner Cloud GmbH <info@hetzner-cloud.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import annotations

DOCUMENTATION = """
---
module: ssh_key

short_description: Create and manage ssh keys on the Hetzner Cloud.


description:
    - Create, update and manage ssh keys on the Hetzner Cloud.

author:
    - Lukas Kaemmerling (@LKaemmerling)

options:
    id:
        description:
            - The ID of the Hetzner Cloud ssh_key to manage.
            - Only required if no ssh_key I(name) is given
        type: int
    name:
        description:
            - The Name of the Hetzner Cloud ssh_key to manage.
            - Only required if no ssh_key I(id) is given or a ssh_key does not exist.
        type: str
    fingerprint:
        description:
            - The Fingerprint of the Hetzner Cloud ssh_key to manage.
            - Only required if no ssh_key I(id) or I(name) is given.
        type: str
    labels:
        description:
            - User-defined labels (key-value pairs)
        type: dict
    public_key:
        description:
            - The Public Key to add.
            - Required if ssh_key does not exist.
        type: str
    force:
        description:
            - Recreate the SSH Key if the public key does not match the one in the API.
        type: bool
        default: false
    state:
        description:
            - State of the ssh_key.
        default: present
        choices: [ absent, present ]
        type: str
extends_documentation_fragment:
- hetzner.hcloud.hcloud

"""

EXAMPLES = """
- name: Create a basic ssh_key
  hetzner.hcloud.ssh_key:
    name: my-ssh_key
    public_key: ssh-rsa AAAjjk76kgf...Xt
    state: present

- name: Create a ssh_key with labels
  hetzner.hcloud.ssh_key:
    name: my-ssh_key
    public_key: ssh-rsa AAAjjk76kgf...Xt
    labels:
      key: value
      mylabel: 123
    state: present

- name: Ensure the ssh_key is absent (remove if needed)
  hetzner.hcloud.ssh_key:
    name: my-ssh_key
    state: absent
"""

RETURN = """
hcloud_ssh_key:
    description: The ssh_key instance
    returned: Always
    type: complex
    contains:
        id:
            description: ID of the ssh_key
            type: int
            returned: Always
            sample: 12345
        name:
            description: Name of the ssh_key
            type: str
            returned: Always
            sample: my-ssh-key
        fingerprint:
            description: Fingerprint of the ssh_key
            type: str
            returned: Always
            sample: b7:2f:30:a0:2f:6c:58:6c:21:04:58:61:ba:06:3b:2f
        public_key:
            description: Public key of the ssh_key
            type: str
            returned: Always
            sample: "ssh-rsa AAAjjk76kgf...Xt"
        labels:
            description: User-defined labels (key-value pairs)
            type: dict
            returned: Always
            sample:
                key: value
                mylabel: 123
"""

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.hcloud import AnsibleHCloud
from ..module_utils.ssh import ssh_public_key_md5_fingerprint
from ..module_utils.vendor.hcloud import HCloudException
from ..module_utils.vendor.hcloud.ssh_keys import BoundSSHKey


class AnsibleHCloudSSHKey(AnsibleHCloud):
    represent = "hcloud_ssh_key"

    hcloud_ssh_key: BoundSSHKey | None = None

    def _prepare_result(self):
        return {
            "id": self.hcloud_ssh_key.id,
            "name": self.hcloud_ssh_key.name,
            "fingerprint": self.hcloud_ssh_key.fingerprint,
            "public_key": self.hcloud_ssh_key.public_key,
            "labels": self.hcloud_ssh_key.labels,
        }

    def _get_ssh_key(self):
        try:
            if self.module.params.get("id") is not None:
                self.hcloud_ssh_key = self.client.ssh_keys.get_by_id(self.module.params.get("id"))
            elif self.module.params.get("fingerprint") is not None:
                self.hcloud_ssh_key = self.client.ssh_keys.get_by_fingerprint(self.module.params.get("fingerprint"))
            elif self.module.params.get("name") is not None:
                self.hcloud_ssh_key = self.client.ssh_keys.get_by_name(self.module.params.get("name"))

        except HCloudException as exception:
            self.fail_json_hcloud(exception)

    def _create_ssh_key(self):
        self.module.fail_on_missing_params(required_params=["name", "public_key"])
        params = {
            "name": self.module.params.get("name"),
            "public_key": self.module.params.get("public_key"),
            "labels": self.module.params.get("labels"),
        }

        if not self.module.check_mode:
            try:
                self.client.ssh_keys.create(**params)
            except HCloudException as exception:
                self.fail_json_hcloud(exception)
        self._mark_as_changed()
        self._get_ssh_key()

    def _update_ssh_key(self):
        name = self.module.params.get("name")
        if name is not None and self.hcloud_ssh_key.name != name:
            self.module.fail_on_missing_params(required_params=["id"])
            if not self.module.check_mode:
                self.hcloud_ssh_key.update(name=name)
            self._mark_as_changed()

        labels = self.module.params.get("labels")
        if labels is not None and self.hcloud_ssh_key.labels != labels:
            if not self.module.check_mode:
                self.hcloud_ssh_key.update(labels=labels)
            self._mark_as_changed()

        public_key = self.module.params.get("public_key")
        if public_key is not None:
            fingerprint = ssh_public_key_md5_fingerprint(public_key)
            if fingerprint != self.hcloud_ssh_key.fingerprint:
                if self.module.params.get("force"):
                    if not self.module.check_mode:
                        self.hcloud_ssh_key.delete()
                        self._create_ssh_key()
                    self._mark_as_changed()
                else:
                    self.module.warn(
                        f"SSH Key '{self.hcloud_ssh_key.name}' in the API has a "
                        f"different public key than the one provided. "
                        f"Use the force=true argument to recreate the SSH Key in the API."
                    )
        self._get_ssh_key()

    def present_ssh_key(self):
        self._get_ssh_key()
        if self.hcloud_ssh_key is None:
            self._create_ssh_key()
        else:
            self._update_ssh_key()

    def delete_ssh_key(self):
        self._get_ssh_key()
        if self.hcloud_ssh_key is not None:
            if not self.module.check_mode:
                try:
                    self.client.ssh_keys.delete(self.hcloud_ssh_key)
                except HCloudException as exception:
                    self.fail_json_hcloud(exception)
            self._mark_as_changed()
        self.hcloud_ssh_key = None

    @classmethod
    def define_module(cls):
        return AnsibleModule(
            argument_spec=dict(
                id={"type": "int"},
                name={"type": "str"},
                public_key={"type": "str"},
                fingerprint={"type": "str"},
                labels={"type": "dict"},
                force={"type": "bool", "default": False},
                state={
                    "choices": ["absent", "present"],
                    "default": "present",
                },
                **super().base_module_arguments(),
            ),
            required_one_of=[["id", "name", "fingerprint"]],
            required_if=[["state", "present", ["name"]]],
            supports_check_mode=True,
        )


def main():
    module = AnsibleHCloudSSHKey.define_module()

    hcloud = AnsibleHCloudSSHKey(module)
    state = module.params.get("state")
    if state == "absent":
        hcloud.delete_ssh_key()
    elif state == "present":
        hcloud.present_ssh_key()

    module.exit_json(**hcloud.get_result())


if __name__ == "__main__":
    main()
