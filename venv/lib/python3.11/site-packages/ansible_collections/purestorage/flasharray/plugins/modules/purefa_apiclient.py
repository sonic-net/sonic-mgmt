#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2020, Simon Dodsley (simon@purestorage.com)
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
module: purefa_apiclient
version_added: '1.5.0'
short_description: Manage FlashArray API Clients
description:
- Enable or disable FlashArray API Clients
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
- purestorage.flasharray.purestorage.fa
"""

EXAMPLES = r"""
- name: Create API token ansible-token
  purestorage.flasharray.purefa_apiclient:
    name: ansible-token
    issuer: "Pure Storage"
    token_ttl: 3000
    role: array_admin
    public_key: "{{lookup('file', 'public_pem_file') }}"
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Disable API CLient
  purestorage.flasharray.purefa_apiclient:
    name: ansible-token
    enabled: false
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Enable API CLient
  purestorage.flasharray.purefa_apiclient:
    name: ansible-token
    enabled: true
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Delete API Client
  purestorage.flasharray.purefa_apiclient:
    state: absent
    name: ansible-token
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
from ansible_collections.purestorage.flasharray.plugins.module_utils.version import (
    LooseVersion,
)

MIN_REQUIRED_API_VERSION = "2.1"


def delete_client(module, array):
    changed = True
    if not module.check_mode:
        res = array.delete_api_clients(names=[module.params["name"]])
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to delete API Client {0}. Error: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def update_client(module, array, client):
    """Update API Client"""
    changed = False
    if client.enabled != module.params["enabled"]:
        changed = True
        if not module.check_mode:
            res = array.patch_api_clients(
                names=[module.params["name"]],
                api_clients=flasharray.ApiClientPatch(enabled=module.params["enabled"]),
            )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to update API Client {0}. Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
    module.exit_json(changed=changed)


def create_client(module, array):
    """Create API Client"""
    changed = True
    if not 1 <= module.params["token_ttl"] <= 86400:
        module.fail_json(msg="token_ttl parameter is out of range (1 to 86400)")
    else:
        token_ttl = module.params["token_ttl"] * 1000
    if not module.params["issuer"]:
        module.params["issuer"] = module.params["name"]
    client = flasharray.ApiClientPost(
        max_role=module.params["role"],
        issuer=module.params["issuer"],
        access_token_ttl_in_ms=token_ttl,
        public_key=module.params["public_key"],
    )
    if not module.check_mode:
        res = array.post_api_clients(names=[module.params["name"]], api_clients=client)
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to create API CLient {0}. Error message: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
        if module.params["enabled"]:
            res = array.patch_api_clients(
                names=[module.params["name"]],
                api_clients=flasharray.ApiClientPatch(enabled=module.params["enabled"]),
            )
            if res.status_code != 200:
                array.delete_api_clients(names=[module.params["name"]])
                module.fail_json(
                    msg="Failed to create API Client {0}. Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefa_argument_spec()
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

    if not HAS_PURESTORAGE:
        module.fail_json(msg="py-pure-client sdk is required for this module")

    array = get_array(module)
    api_version = array.get_rest_version()

    if LooseVersion(MIN_REQUIRED_API_VERSION) > LooseVersion(api_version):
        module.fail_json(
            msg="FlashArray REST version not supported. "
            "Minimum version required: {0}".format(MIN_REQUIRED_API_VERSION)
        )
    state = module.params["state"]

    try:
        client = list(array.get_api_clients(names=[module.params["name"]]).items)[0]
        exists = True
    except Exception:
        exists = False

    if not exists and state == "present":
        create_client(module, array)
    elif exists and state == "present":
        update_client(module, array, client)
    elif exists and state == "absent":
        delete_client(module, array)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
