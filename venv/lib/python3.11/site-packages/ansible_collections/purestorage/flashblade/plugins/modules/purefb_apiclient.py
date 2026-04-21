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
module: purefb_apiclient
version_added: '1.6.0'
short_description: Manage FlashBlade API Clients
description:
- Enable or disable FlashBlade API Clients
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
    - Name of the API Client
    type: str
    required: true
  state:
    description:
    - Define whether the API client should exist or not.
    default: present
    choices: [ absent, present ]
    type: str
  role:
    description:
    - The maximum role allowed for ID Tokens issued by this API client
    type: str
    choices: [readonly, ops_admin, storage_admin, array_admin]
  issuer:
    description:
    - The name of the identity provider that will be issuing ID Tokens for this API client
    - If not specified, defaults to the API client name, I(name).
    type: str
  public_key:
    description:
    - The API clients PEM formatted (Base64 encoded) RSA public key.
    - Include the I(—–BEGIN PUBLIC KEY—–) and I(—–END PUBLIC KEY—–) lines
    type: str
  token_ttl:
    description:
    - Time To Live length in seconds for the exchanged access token
    - Range is 1 second to 1 day (86400 seconds)
    type: int
    default: 86400
  enabled:
    description:
    - State of the API Client Key
    type: bool
    default: true
extends_documentation_fragment:
- purestorage.flashblade.purestorage.fb
"""

EXAMPLES = r"""
- name: Create API token ansible-token
  purestorage.flashblade.purefb_apiclient:
    name: ansible_token
    issuer: "Pure_Storage"
    token_ttl: 3000
    role: array_admin
    public_key: "{{lookup('file', 'public_pem_file') }}"
    fb_url: 10.10.10.2
    api_token: T-68618f31-0c9e-4e57-aa44-5306a2cf10e3

- name: Disable API CLient
  purestorage.flashblade.purefb_apiclient:
    name: ansible_token
    enabled: false
    fb_url: 10.10.10.2
    api_token: T-68618f31-0c9e-4e57-aa44-5306a2cf10e3

- name: Enable API CLient
  purestorage.flashblade.purefb_apiclient:
    name: ansible_token
    enabled: true
    fb_url: 10.10.10.2
    api_token: T-68618f31-0c9e-4e57-aa44-5306a2cf10e3

- name: Delete API Client
  purestorage.flashblade.purefb_apiclient:
    state: absent
    name: ansible_token
    fb_url: 10.10.10.2
    api_token: T-68618f31-0c9e-4e57-aa44-5306a2cf10e3
"""

RETURN = r"""
"""

HAS_PURESTORAGE = True
try:
    from pypureclient.flashblade import ApiClient, ApiClientsPost, ReferenceWritable
except ImportError:
    HAS_PURESTORAGE = False

import re
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_system,
    purefb_argument_spec,
)


def delete_client(module, blade):
    changed = True
    if not module.check_mode:
        res = blade.delete_api_clients(names=[module.params["name"]])
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to delete API Client {0}".format(module.params["name"])
            )
    module.exit_json(changed=changed)


def update_client(module, blade, client):
    """Update API Client"""
    changed = False
    if client.enabled != module.params["enabled"]:
        changed = True
        if not module.check_mode:
            res = blade.patch_api_clients(
                names=[module.params["name"]],
                api_clients=ApiClient(enabled=module.params["enabled"]),
            )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to update API Client {0}".format(module.params["name"])
                )
    module.exit_json(changed=changed)


def create_client(module, blade):
    """Create API Client"""
    changed = True
    if not module.params["public_key"]:
        module.fail_json(msg="public_key is required to create an API Client")
    if not 1 <= module.params["token_ttl"] <= 86400:
        module.fail_json(msg="token_ttl parameter is out of range (1 to 86400)")
    else:
        token_ttl = module.params["token_ttl"] * 1000
    if not module.params["issuer"]:
        module.params["issuer"] = module.params["name"]
    if not module.check_mode:
        api_client = ApiClientsPost(
            max_role=ReferenceWritable(name=module.params["role"]),
            issuer=module.params["issuer"],
            access_token_ttl_in_ms=token_ttl,
            public_key=module.params["public_key"],
        )
        res = blade.post_api_clients(
            names=[module.params["name"]], api_client=api_client
        )
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to create API Client {0}. Error message: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
        if module.params["enabled"]:
            attr = ApiClient(enabled=True)
            res = blade.patch_api_clients(
                api_clients=attr, names=[module.params["name"]]
            )
            if res.status_code != 200:
                module.warn(
                    "API Client {0} created by enable failed. Please investigate.".format(
                        module.params["name"]
                    )
                )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(
            state=dict(type="str", default="present", choices=["absent", "present"]),
            enabled=dict(type="bool", default=True),
            name=dict(type="str", required=True),
            role=dict(
                type="str",
                choices=["readonly", "ops_admin", "storage_admin", "array_admin"],
            ),
            public_key=dict(type="str", no_log=True),
            token_ttl=dict(type="int", default=86400, no_log=False),
            issuer=dict(type="str"),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)
    pattern = re.compile("^[a-zA-Z0-9]([a-zA-Z0-9_]{0,54}[a-zA-Z0-9])?$")
    if module.params["issuer"]:
        if not pattern.match(module.params["issuer"]):
            module.fail_json(
                msg="API Client Issuer name {0} does not conform to required naming convention".format(
                    module.params["issuer"]
                )
            )
    if not pattern.match(module.params["name"]):
        module.fail_json(
            msg="Object Store Virtual Host name {0} does not conform to required naming convention".format(
                module.params["name"]
            )
        )
    if not HAS_PURESTORAGE:
        module.fail_json(msg="py-pure-client sdk is required for this module")

    blade = get_system(module)
    state = module.params["state"]

    exists = bool(
        blade.get_api_clients(names=[module.params["name"]]).status_code == 200
    )
    if exists:
        client = list(blade.get_api_clients(names=[module.params["name"]]).items)[0]

    if not exists and state == "present":
        create_client(module, blade)
    elif exists and state == "present":
        update_client(module, blade, client)
    elif exists and state == "absent":
        delete_client(module, blade)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
