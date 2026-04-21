#!/usr/bin/python

# Copyright: (c) 2020, Hetzner Cloud GmbH <info@hetzner-cloud.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import annotations

DOCUMENTATION = """
---
module: certificate

short_description: Create and manage certificates on the Hetzner Cloud.


description:
    - Create, update and manage certificates on the Hetzner Cloud.

author:
    - Lukas Kaemmerling (@lkaemmerling)

options:
    id:
        description:
            - The ID of the Hetzner Cloud certificate to manage.
            - Only required if no certificate I(name) is given
        type: int
    name:
        description:
            - The Name of the Hetzner Cloud certificate to manage.
            - Only required if no certificate I(id) is given or a certificate does not exist.
        type: str
    labels:
        description:
            - User-defined labels (key-value pairs)
        type: dict
    certificate:
        description:
            - Certificate and chain in PEM format, in order so that each record directly certifies the one preceding.
            - Required if certificate does not exist and I(type=uploaded).
        type: str
    private_key:
        description:
            - Certificate key in PEM format.
            - Required if certificate does not exist and I(type=uploaded).
        type: str
    domain_names:
        description:
            - Domains and subdomains that should be contained in the Certificate issued by Let's Encrypt.
            - Required if I(type=managed).
        type: list
        default: [ ]
        elements: str
    type:
        description:
            - Choose between uploading a Certificate in PEM format or requesting a managed Let's Encrypt Certificate.
        default: uploaded
        choices: [ uploaded, managed ]
        type: str
    state:
        description:
            - State of the certificate.
        default: present
        choices: [ absent, present ]
        type: str
extends_documentation_fragment:
- hetzner.hcloud.hcloud

"""

EXAMPLES = """
- name: Create a basic certificate
  hetzner.hcloud.certificate:
    name: my-certificate
    certificate: -----BEGIN CERTIFICATE-----...
    private_key: -----BEGIN PRIVATE KEY-----...
    state: present

- name: Create a certificate with labels
  hetzner.hcloud.certificate:
    name: my-certificate
    certificate: -----BEGIN CERTIFICATE-----...
    private_key: -----BEGIN PRIVATE KEY-----...
    labels:
      key: value
      mylabel: 123
    state: present

- name: Create a managed certificate
  hetzner.hcloud.certificate:
    name: my-certificate
    type: managed
    domain_names:
      - example.com
      - www.example.com
    state: present

- name: Ensure the certificate is absent (remove if needed)
  hetzner.hcloud.certificate:
    name: my-certificate
    state: absent
"""

RETURN = """
hcloud_certificate:
    description: The certificate instance
    returned: Always
    type: complex
    contains:
        id:
            description: Numeric identifier of the certificate
            returned: always
            type: int
            sample: 1937415
        name:
            description: Name of the certificate
            returned: always
            type: str
            sample: my website cert
        fingerprint:
            description: Fingerprint of the certificate
            returned: always
            type: str
            sample: "03:c7:55:9b:2a:d1:04:17:09:f6:d0:7f:18:34:63:d4:3e:5f"
        certificate:
            description: Certificate and chain in PEM format
            returned: always
            type: str
            sample: "-----BEGIN CERTIFICATE-----..."
        domain_names:
            description: List of Domains and Subdomains covered by the Certificate
            returned: always
            type: dict
        not_valid_before:
            description: Point in time when the Certificate becomes valid (in ISO-8601 format)
            returned: always
            type: str
        not_valid_after:
            description: Point in time when the Certificate stops being valid (in ISO-8601 format)
            returned: always
            type: str
        labels:
            description: User-defined labels (key-value pairs)
            returned: always
            type: dict
"""

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.hcloud import AnsibleHCloud
from ..module_utils.vendor.hcloud import HCloudException
from ..module_utils.vendor.hcloud.certificates import BoundCertificate


class AnsibleHCloudCertificate(AnsibleHCloud):
    represent = "hcloud_certificate"

    hcloud_certificate: BoundCertificate | None = None

    def _prepare_result(self):
        return {
            "id": self.hcloud_certificate.id,
            "name": self.hcloud_certificate.name,
            "type": self.hcloud_certificate.type,
            "fingerprint": self.hcloud_certificate.fingerprint,
            "certificate": self.hcloud_certificate.certificate,
            "not_valid_before": self.hcloud_certificate.not_valid_before.isoformat(),
            "not_valid_after": self.hcloud_certificate.not_valid_after.isoformat(),
            "domain_names": self.hcloud_certificate.domain_names,
            "labels": self.hcloud_certificate.labels,
        }

    def _get_certificate(self):
        try:
            if self.module.params.get("id") is not None:
                self.hcloud_certificate = self.client.certificates.get_by_id(self.module.params.get("id"))
            elif self.module.params.get("name") is not None:
                self.hcloud_certificate = self.client.certificates.get_by_name(self.module.params.get("name"))

        except HCloudException as exception:
            self.fail_json_hcloud(exception)

    def _create_certificate(self):
        self.module.fail_on_missing_params(required_params=["name"])

        params = {
            "name": self.module.params.get("name"),
            "labels": self.module.params.get("labels"),
        }
        if self.module.params.get("type") == "uploaded":
            self.module.fail_on_missing_params(required_params=["certificate", "private_key"])
            params["certificate"] = self.module.params.get("certificate")
            params["private_key"] = self.module.params.get("private_key")
            if not self.module.check_mode:
                try:
                    self.client.certificates.create(**params)
                except HCloudException as exception:
                    self.fail_json_hcloud(exception)
        else:
            self.module.fail_on_missing_params(required_params=["domain_names"])
            params["domain_names"] = self.module.params.get("domain_names")
            if not self.module.check_mode:
                try:
                    resp = self.client.certificates.create_managed(**params)
                    # Action should take 60 to 90 seconds on average, wait for 5m to
                    # allow DNS or Let's Encrypt slowdowns.
                    resp.action.wait_until_finished(max_retries=62)  # 62 retries >= 302 seconds
                except HCloudException as exception:
                    self.fail_json_hcloud(exception)

        self._mark_as_changed()
        self._get_certificate()

    def _update_certificate(self):
        try:
            name = self.module.params.get("name")
            if name is not None and self.hcloud_certificate.name != name:
                self.module.fail_on_missing_params(required_params=["id"])
                if not self.module.check_mode:
                    self.hcloud_certificate.update(name=name)
                self._mark_as_changed()

            labels = self.module.params.get("labels")
            if labels is not None and self.hcloud_certificate.labels != labels:
                if not self.module.check_mode:
                    self.hcloud_certificate.update(labels=labels)
                self._mark_as_changed()
        except HCloudException as exception:
            self.fail_json_hcloud(exception)
        self._get_certificate()

    def present_certificate(self):
        self._get_certificate()
        if self.hcloud_certificate is None:
            self._create_certificate()
        else:
            self._update_certificate()

    def delete_certificate(self):
        self._get_certificate()
        if self.hcloud_certificate is not None:
            if not self.module.check_mode:
                try:
                    self.client.certificates.delete(self.hcloud_certificate)
                except HCloudException as exception:
                    self.fail_json_hcloud(exception)
            self._mark_as_changed()
        self.hcloud_certificate = None

    @classmethod
    def define_module(cls):
        return AnsibleModule(
            argument_spec=dict(
                id={"type": "int"},
                name={"type": "str"},
                type={
                    "choices": ["uploaded", "managed"],
                    "default": "uploaded",
                },
                domain_names={"type": "list", "elements": "str", "default": []},
                certificate={"type": "str"},
                private_key={"type": "str", "no_log": True},
                labels={"type": "dict"},
                state={
                    "choices": ["absent", "present"],
                    "default": "present",
                },
                **super().base_module_arguments(),
            ),
            required_one_of=[["id", "name"]],
            required_if=[["state", "present", ["name"]]],
            supports_check_mode=True,
        )


def main():
    module = AnsibleHCloudCertificate.define_module()

    hcloud = AnsibleHCloudCertificate(module)
    state = module.params.get("state")
    if state == "absent":
        hcloud.delete_certificate()
    elif state == "present":
        hcloud.present_certificate()

    module.exit_json(**hcloud.get_result())


if __name__ == "__main__":
    main()
