#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 20224, Simon Dodsley (simon@purestorage.com)
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
module: purefb_saml
version_added: '1.19.0'
short_description: Manage FlashBlade SAML2 service and identity providers
description:
- Enable or disable FlashBlade SAML2 providers
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
    - Name of the SAML2 identity provider (IdP)
    type: str
    required: true
  state:
    description:
    - Define whether the API client should exist or not, or test.
    default: present
    choices: [ absent, present, test ]
    type: str
  url:
    description:
    - The URL of the identity provider
    type: str
  entity_id:
    description:
    - A globally unique name for the identity provider
    type: str
    version_added: '1.21.0'
  array_url:
    description:
    - The URL of the FlashBlade
    type: str
  metadata_url:
    description:
    - The URL of the identity provider metadata
    type: str
  enabled:
    description:
    - Defines the enabled state of the identity provider
    default: false
    type: bool
  encrypt_asserts:
    description:
    - If set to true, SAML assertions will be encrypted by the identity provider
    default: false
    type: bool
  sign_request:
    description:
    - If set to true, SAML requests will be signed by the service provider.
    default: false
    type: bool
  x509_cert:
    description:
    - The X509 certificate that the service provider uses to verify the SAML
      response signature from the identity provider
    type: str
  decryption_credential:
    description:
    - The credential used by the service provider to decrypt encrypted SAML assertions from the identity provider
    type: str
  signing_credential:
    description:
    - The credential used by the service provider to sign SAML requests
    type: str
extends_documentation_fragment:
- purestorage.flashblade.purestorage.fb
"""

EXAMPLES = r"""
- name: Create (disabled) SAML2 SSO with only metadata URL
  purestorage.flashblade.purefb_saml:
    name: myIDP
    array_url: "https://10.10.10.2"
    metadata_url: "https://myidp.acme.com/adfs/ls"
    x509_cert: "{{lookup('file', 'x509_cert_file') }}"
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6

- name: Enable SAML2 SSO
  purestorage.flashblade.purefb_saml:
    name: myISO
    enabled: true
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6

- name: Delete SAML2 SSO
  purestorage.flashblade.purefb_saml:
    state: absent
    name: myIDP
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
"""

RETURN = r"""
"""

HAS_PURESTORAGE = True
try:
    from pypureclient.flashblade import (
        Saml2Sso,
        Saml2SsoPost,
        Saml2SsoSp,
        Saml2SsoIdp,
        ReferenceWriteable,
    )
except ImportError:
    HAS_PURESTORAGE = False

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_system,
    purefb_argument_spec,
)

MIN_REQUIRED_API_VERSION = "2.15"
TEST_API_VERSION = "2.16"


def test_saml(module, blade):
    """Test SAML2 IdP configuration"""
    test_response = []
    response = list(blade.get_sso_saml2_idps_test(names=[module.params["name"]]).items)
    for component in range(len(response)):
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


def delete_saml(module, blade):
    """Delete SSO SAML2 IdP"""
    changed = True
    if not module.check_mode:
        res = blade.delete_sso_saml2_idps(names=[module.params["name"]])
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to delete SAML2 IdP {0}. Error: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def update_saml(module, blade):
    """Update SSO SAML2 IdP"""
    changed = False
    current_idp = list(blade.get_sso_saml2_idps(names=[module.params["name"]]).items)[0]
    old_idp = {
        "array_url": current_idp.array_url,
        "enabled": current_idp.enabled,
        "sp_sign_cred": getattr(current_idp.sp.signing_credential, "name", None),
        "sp_decrypt_cred": getattr(current_idp.sp.decryption_credential, "name", None),
        "id_metadata": current_idp.idp.metadata_url,
        "id_entity": getattr(current_idp.idp, "entity_id", "None"),
        "id_url": getattr(current_idp.idp, "url", None),
        "id_sign_enabled": current_idp.idp.sign_request_enabled,
        "id_encrypt_enabled": current_idp.idp.encrypt_assertion_enabled,
        "id_cert": current_idp.idp.verification_certificate,
    }
    if module.params["entity_id"]:
        new_entity = module.params["entity_id"]
    else:
        new_entity = old_idp["id_entity"]
    if module.params["url"]:
        new_url = module.params["url"]
    else:
        new_url = old_idp["id_url"]
    if module.params["array_url"]:
        new_array_url = module.params["array_url"]
    else:
        new_array_url = old_idp["array_url"]
    if module.params["enabled"] != old_idp["enabled"]:
        new_enabled = module.params["enabled"]
    else:
        new_enabled = old_idp["enabled"]
    if module.params["sign_request"] != old_idp["id_sign_enabled"]:
        new_sign = module.params["sign_request"]
    else:
        new_sign = old_idp["id_sign_enabled"]
    if module.params["encrypt_asserts"] != old_idp["id_encrypt_enabled"]:
        new_encrypt = module.params["encrypt_asserts"]
    else:
        new_encrypt = old_idp["id_encrypt_enabled"]
    if module.params["signing_credential"]:
        new_sign_cred = module.params["signing_credential"]
    else:
        new_sign_cred = old_idp["sp_sign_cred"]
    if module.params["decryption_credential"]:
        new_decrypt_cred = module.params["decryption_credential"]
    else:
        new_decrypt_cred = old_idp["sp_decrypt_cred"]
    if module.params["metadata_url"]:
        new_meta_url = module.params["metadata_url"]
    else:
        new_meta_url = old_idp["id_metadata"]
    if module.params["x509_cert"]:
        new_cert = module.params["x509_cert"]
    else:
        new_cert = old_idp["id_cert"]
    new_idp = {
        "array_url": new_array_url,
        "enabled": new_enabled,
        "sp_sign_cred": new_sign_cred,
        "sp_decrypt_cred": new_decrypt_cred,
        "id_entity": new_entity,
        "id_metadata": new_meta_url,
        "id_sign_enabled": new_sign,
        "id_encrypt_enabled": new_encrypt,
        "id_url": new_url,
        "id_cert": new_cert,
    }
    if old_idp != new_idp:
        changed = True
        decrypt = None
        signing = None
        if not module.check_mode:
            if new_idp["sp_decrypt_cred"]:
                decrypt = ReferenceWriteable(name=new_idp["sp_decrypt_cred"])
            if new_idp["sp_sign_cred"]:
                decrypt = ReferenceWriteable(name=new_idp["sp_sign_cred"])
            sp = Saml2SsoSp(
                decryption_credential=decrypt,
                signing_credential=signing,
            )
            idp = Saml2SsoIdp(
                url=new_idp["id_url"],
                metadata_url=new_idp["id_metadata"],
                entity_id=new_idp["id_entity"],
                sign_request_enabled=new_idp["id_sign_enabled"],
                encrypt_assertion_enabled=new_idp["id_encrypt_enabled"],
                verification_certificate=new_idp["id_cert"],
            )
            res = blade.patch_sso_saml2_idps(
                idp=Saml2Sso(
                    array_url=new_idp["array_url"],
                    idp=idp,
                    sp=sp,
                    enabled=new_idp["enabled"],
                ),
                names=[module.params["name"]],
            )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to update SAML2 IdP {0}. Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
    module.exit_json(changed=changed)


def create_saml(module, blade):
    """Create SAML2 IdP"""
    changed = True
    decrypt = None
    signing = None
    if not module.check_mode:
        if module.params["decryption_credential"]:
            decrypt = ReferenceWriteable(name=module.params["decryption_credential"])
        if module.params["signing_credential"]:
            signing = ReferenceWriteable(name=module.params["signing_credential"])
        sp = Saml2SsoSp(
            decryption_credential=decrypt,
            signing_credential=signing,
        )
        idp = Saml2SsoIdp(
            url=module.params["url"],
            metadata_url=module.params["metadata_url"],
            entity_id=module.params["entity_id"],
            sign_request_enabled=module.params["sign_request"],
            encrypt_assertion_enabled=module.params["encrypt_asserts"],
            verification_certificate=module.params["x509_cert"],
        )
        if not module.check_mode:
            res = blade.post_sso_saml2_idps(
                idp=Saml2SsoPost(array_url=module.params["array_url"], idp=idp, sp=sp),
                names=[module.params["name"]],
            )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to create SAML2 Identity Provider {0}. Error message: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
            if module.params["enabled"]:
                res = blade.patch_sso_saml2_idps(
                    idp=Saml2Sso(enabled=module.params["enabled"]),
                    names=[module.params["name"]],
                )
                if res.status_code != 200:
                    blade.delete_sso_saml2_idps(names=[module.params["name"]])
                    module.fail_json(
                        msg="Failed to create SAML2 Identity Provider {0}. Error message: {1}".format(
                            module.params["name"], res.errors[0].message
                        )
                    )

    module.exit_json(changed=changed)


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(
            state=dict(
                type="str", default="present", choices=["absent", "present", "test"]
            ),
            name=dict(type="str", required=True),
            url=dict(type="str"),
            array_url=dict(type="str"),
            entity_id=dict(type="str"),
            metadata_url=dict(type="str"),
            x509_cert=dict(type="str", no_log=True),
            signing_credential=dict(type="str"),
            decryption_credential=dict(type="str"),
            enabled=dict(type="bool", default=False),
            encrypt_asserts=dict(type="bool", default=False),
            sign_request=dict(type="bool", default=False),
        )
    )

    required_if = [
        ["encrypt_asserts", True, ["decryption_credential"]],
        ["sign_request", True, ["signing_credential"]],
    ]

    module = AnsibleModule(
        argument_spec, supports_check_mode=True, required_if=required_if
    )

    if not HAS_PURESTORAGE:
        module.fail_json(msg="py-pure-client sdk is required for this module")

    blade = get_system(module)
    api_version = list(blade.get_versions().items)

    if MIN_REQUIRED_API_VERSION not in api_version:
        module.fail_json(
            msg="FlashBlade REST version not supported. "
            "Minimum version required: {0}".format(MIN_REQUIRED_API_VERSION)
        )
    state = module.params["state"]
    if state == "test" and TEST_API_VERSION not in api_version:
        module.fail_json(
            msg="FlashBlade REST version not supported for SAML2 testing. "
            "Minimum version required: {0}".format(MIN_REQUIRED_API_VERSION)
        )

    exists = bool(
        blade.get_sso_saml2_idps(names=[module.params["name"]]).status_code == 200
    )
    if not exists and state == "present":
        create_saml(module, blade)
    elif exists and state == "present":
        update_saml(module, blade)
    elif exists and state == "absent":
        delete_saml(module, blade)
    elif exists and state == "test":
        test_saml(module, blade)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
