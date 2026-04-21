#!/usr/bin/python

# Copyright: (c) 2020, Hetzner Cloud GmbH <info@hetzner-cloud.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import annotations

DOCUMENTATION = """
---
module: certificate_info
short_description: Gather infos about your Hetzner Cloud certificates.
description:
    - Gather facts about your Hetzner Cloud certificates.
author:
    - Lukas Kaemmerling (@LKaemmerling)
options:
    id:
        description:
            - The ID of the certificate you want to get.
            - The module will fail if the provided ID is invalid.
        type: int
    name:
        description:
            - The name of the certificate you want to get.
        type: str
    label_selector:
        description:
            - The label selector for the certificate you want to get.
        type: str
extends_documentation_fragment:
- hetzner.hcloud.hcloud

"""

EXAMPLES = """
- name: Gather hcloud certificate infos
  hetzner.hcloud.certificate_info:
  register: output
- name: Print the gathered infos
  debug:
    var: output.hcloud_certificate_info
"""

RETURN = """
hcloud_certificate_info:
    description: The certificate instances
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


class AnsibleHCloudCertificateInfo(AnsibleHCloud):
    represent = "hcloud_certificate_info"

    hcloud_certificate_info: list[BoundCertificate] | None = None

    def _prepare_result(self):
        tmp = []

        for certificate in self.hcloud_certificate_info:
            if certificate is None:
                continue

            tmp.append(
                {
                    "id": certificate.id,
                    "name": certificate.name,
                    "fingerprint": certificate.fingerprint,
                    "certificate": certificate.certificate,
                    "not_valid_before": certificate.not_valid_before.isoformat(),
                    "not_valid_after": certificate.not_valid_after.isoformat(),
                    "domain_names": certificate.domain_names,
                    "labels": certificate.labels,
                }
            )
        return tmp

    def get_certificates(self):
        try:
            if self.module.params.get("id") is not None:
                self.hcloud_certificate_info = [self.client.certificates.get_by_id(self.module.params.get("id"))]
            elif self.module.params.get("name") is not None:
                self.hcloud_certificate_info = [self.client.certificates.get_by_name(self.module.params.get("name"))]
            elif self.module.params.get("label_selector") is not None:
                self.hcloud_certificate_info = self.client.certificates.get_all(
                    label_selector=self.module.params.get("label_selector")
                )
            else:
                self.hcloud_certificate_info = self.client.certificates.get_all()

        except HCloudException as exception:
            self.fail_json_hcloud(exception)

    @classmethod
    def define_module(cls):
        return AnsibleModule(
            argument_spec=dict(
                id={"type": "int"},
                name={"type": "str"},
                label_selector={"type": "str"},
                **super().base_module_arguments(),
            ),
            supports_check_mode=True,
        )


def main():
    module = AnsibleHCloudCertificateInfo.define_module()
    hcloud = AnsibleHCloudCertificateInfo(module)

    hcloud.get_certificates()
    result = hcloud.get_result()

    ansible_info = {"hcloud_certificate_info": result["hcloud_certificate_info"]}
    module.exit_json(**ansible_info)


if __name__ == "__main__":
    main()
