#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2021, Simon Dodsley (simon@purestorage.com)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: purefa_kmip
version_added: '1.10.0'
short_description: Manage FlashArray KMIP server objects
description:
- Manage FlashArray KMIP Server objects
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
    - Name of the KMIP server object
    type: str
    required: true
  certificate:
    description:
    - Name of existing certifcate used to verify FlashArray
      authenticity to the KMIP server.
    - Use the I(purestorage.flasharray.purefa_certs) module to create certificates.
    type: str
  state:
    description:
    - Action for the module to perform
    default: present
    choices: [ absent, present, test ]
    type: str
  ca_certificate:
    type: str
    description:
    - The text of the CA certificate for the KMIP server.
    - Includes the "-----BEGIN CERTIFICATE-----" and "-----END CERTIFICATE-----" lines
    - Does not exceed 3000 characters in length
  uris:
    type: list
    elements: str
    description:
    - A list of URIs for the configured KMIP servers.
extends_documentation_fragment:
- purestorage.flasharray.purestorage.fa
"""

EXAMPLES = r"""
- name: Create KMIP obejct
  purestorage.flasharray.purefa_kmip:
    name: foo
    certificate: bar
    ca_certificate: "{{lookup('file', 'example.crt') }}"
    uris:
    - 1.1.1.1:8888
    - 2.3.3.3:9999
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Delete KMIP object
  purestorage.flasharray.purefa_kmip:
    name: foo
    state: absent
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Update KMIP object
  purestorage.flasharray.purefa_kmip:
    name: foo
    ca_certificate: "{{lookup('file', 'example2.crt') }}"
    uris:
    - 3.3.3.3:8888
    - 4.4.4.4:9999
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
"""

RETURN = r"""
"""

HAS_PURESTORAGE = True
try:
    from pypureclient import flasharray
except ImportError:
    HAS_PURESTORAGE = False

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flasharray.plugins.module_utils.purefa import (
    get_array,
    purefa_argument_spec,
)


def test_kmip(module, array):
    """Test KMIP object configuration"""
    test_response = []
    response = list(array.get_kmip_test(names=[module.params["name"]]).items)
    for component in range(0, len(response)):
        if response[component].enabled:
            enabled = "true"
        else:
            enabled = "false"
        if response[component].success:
            success = "true"
        else:
            success = "false"
        test_response.append(
            {
                "component_address": response[component].component_address,
                "component_name": response[component].component_name,
                "description": response[component].description,
                "destination": response[component].destination,
                "enabled": enabled,
                "result_details": getattr(response[component], "result_details", ""),
                "success": success,
                "test_type": response[component].test_type,
                "resource_name": response[component].resource.name,
            }
        )
    module.exit_json(changed=True, test_response=test_response)


def update_kmip(module, array):
    """Update existing KMIP object"""
    changed = False
    current_kmip = list(array.get_kmip(names=[module.params["name"]]).items)[0]
    if (
        module.params["certificate"]
        and current_kmip.certificate.name != module.params["certificate"]
    ):
        if (
            array.get_certificates(names=[module.params["certificate"]]).status_code
            != 200
        ):
            module.fail_json(
                msg="Array certificate {0} does not exist.".format(
                    module.params["certificate"]
                )
            )
        changed = True
        certificate = module.params["certificate"]
    else:
        certificate = current_kmip.certificate.name
    if module.params["uris"] and sorted(current_kmip.uris) != sorted(
        module.params["uris"]
    ):
        changed = True
        uris = sorted(module.params["uris"])
    else:
        uris = sorted(current_kmip.uris)
    if (
        module.params["ca_certificate"]
        and module.params["ca_certificate"] != current_kmip.ca_certificate
    ):
        changed = True
        ca_cert = module.params["ca_certificate"]
    else:
        ca_cert = current_kmip.ca_certificate
    if not module.check_mode:
        if changed:
            kmip = flasharray.KmipPost(
                uris=uris,
                ca_certificate=ca_cert,
                certificate=flasharray.ReferenceNoId(name=certificate),
            )
            res = array.patch_kmip(names=[module.params["name"]], kmip=kmip)
            if res.status_code != 200:
                module.fail_json(
                    msg="Updating existing KMIP object {0} failed. Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )

    module.exit_json(changed=changed)


def create_kmip(module, array):
    """Create KMIP object"""
    if array.get_certificates(names=[module.params["certificate"]]).status_code != 200:
        module.fail_json(
            msg="Array certificate {0} does not exist.".format(
                module.params["certificate"]
            )
        )
    changed = True
    kmip = flasharray.KmipPost(
        uris=sorted(module.params["uris"]),
        ca_certificate=module.params["ca_certificate"],
        certificate=flasharray.ReferenceNoId(name=module.params["certificate"]),
    )
    if not module.check_mode:
        res = array.post_kmip(names=[module.params["name"]], kmip=kmip)
        if res.status_code != 200:
            module.fail_json(
                msg="Creating KMIP object {0} failed. Error: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def delete_kmip(module, array):
    """Delete existing KMIP object"""
    changed = True
    if not module.check_mode:
        res = array.delete_kmip(names=[module.params["name"]])
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to delete {0} KMIP object. Error: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            state=dict(
                type="str",
                default="present",
                choices=["absent", "present", "test"],
            ),
            name=dict(type="str", required=True),
            certificate=dict(type="str"),
            ca_certificate=dict(type="str", no_log=True),
            uris=dict(type="list", elements="str"),
        )
    )

    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True,
    )

    if not HAS_PURESTORAGE:
        module.fail_json(msg="py-pure-client sdk is required for this module")

    array = get_array(module)

    state = module.params["state"]
    exists = bool(array.get_kmip(names=[module.params["name"]]).status_code == 200)
    if module.params["certificate"] and len(module.params["certificate"]) > 3000:
        module.fail_json(msg="Certificate exceeds 3000 characters")

    if not exists and state == "present":
        create_kmip(module, array)
    elif exists and state == "present":
        update_kmip(module, array)
    elif exists and state == "absent":
        delete_kmip(module, array)
    elif exists and state == "test":
        test_kmip(module, array)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
