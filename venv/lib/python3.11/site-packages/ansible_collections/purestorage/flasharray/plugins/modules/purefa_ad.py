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
module: purefa_ad
version_added: '1.9.0'
short_description: Manage FlashArray Active Directory Account
description:
- Add or delete FlashArray Active Directory Account
- FlashArray allows the creation of one AD computer account, or joining of an
  existing AD computer account.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
    - Name of the AD account
    type: str
    required: true
  state:
    description:
    - Define whether the AD sccount is deleted or not
    default: present
    choices: [ absent, present ]
    type: str
  computer:
    description:
    -  The common name of the computer account to be created in the Active Directory domain.
    - If not specified, defaults to the name of the Active Directory configuration.
    type: str
  domain:
    description:
    - The Active Directory domain to join
    type: str
  username:
    description:
    - A user capable of creating a computer account within the domain
    type: str
  password:
    description:
    - Password string for I(username)
    type: str
  directory_servers:
    description:
    - A list of directory servers that will be used for lookups related to user authorization
    - Accepted server formats are IP address and DNS name
    - All specified servers must be registered to the domain appropriately in the array
      configured DNS and are only communicated with over the secure LDAP (LDAPS) protocol.
      If not specified, servers are resolved for the domain in DNS
    - The specified list can have a maximum length of 1, or 3 for Purity 6.1.6 or higher.
      If more are provided only the first allowed count used.
    type: list
    elements: str
  kerberos_servers:
    description:
    - A list of key distribution servers to use for Kerberos protocol
    - Accepted server formats are IP address and DNS name
    - All specified servers must be registered to the domain appropriately in the array
      configured DNS and are only communicated with over the secure LDAP (LDAPS) protocol.
      If not specified, servers are resolved for the domain in DNS.
    - The specified list can have a maximum length of 1, or 3 for Purity 6.1.6 or higher.
      If more are provided only the first allowed count used.
    type: list
    elements: str
  local_only:
    description:
    - Do a local-only delete of an active directory account
    type: bool
    default: false
  join_ou:
    description:
    - Distinguished name of organization unit in which the computer account
      should be created when joining the domain. e.g. OU=Arrays,OU=Storage.
    - The B(DC=...) components can be omitted.
    - If left empty, defaults to B(CN=Computers).
    - Requires Purity//FA 6.1.8 or higher
    type: str
    version_added: '1.10.0'
  tls:
    description:
    - TLS mode for communication with domain controllers.
    type: str
    choices: [ required, optional ]
    default: required
    version_added: '1.14.0'
  join_existing:
    description:
    - If specified as I(true), the domain is searched for a pre-existing
      computer account to join to, and no new account will be created within the domain.
      The C(username) specified when joining a pre-existing account must have
      permissions to 'read all properties from' and 'reset the password of'
      the pre-existing account. C(join_ou) will be read from the pre-existing
      account and cannot be specified when joining to an existing account
    type: bool
    default: false
    version_added: '1.14.0'
extends_documentation_fragment:
- purestorage.flasharray.purestorage.fa
"""

EXAMPLES = r"""
- name: Create new AD account
  purestorage.flasharray.purefa_ad:
    name: ad_account
    computer: FLASHARRAY
    domain: acme.com
    join_ou: "OU=Acme,OU=Dev"
    username: Administrator
    password: Password
    kerberos_servers:
    - kdc.acme.com
    directory_servers:
    - ldap.acme.com
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Delete AD account locally
  purestorage.flasharray.purefa_ad:
    name: ad_account
    local_only: true
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Fully delete AD account. Note that correct AD permissions are required
  purestorage.flasharray.purefa_ad:
    name: ad_account
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
"""

RETURN = r"""
"""

HAS_PURESTORAGE = True
try:
    from pypureclient.flasharray import ActiveDirectoryPost, ActiveDirectoryPatch
except ImportError:
    HAS_PURESTORAGE = False

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flasharray.plugins.module_utils.version import (
    LooseVersion,
)
from ansible_collections.purestorage.flasharray.plugins.module_utils.purefa import (
    get_array,
    purefa_argument_spec,
)

MIN_REQUIRED_API_VERSION = "2.2"
SERVER_API_VERSION = "2.6"
MIN_JOIN_OU_API_VERSION = "2.8"
MIN_TLS_API_VERSION = "2.15"


def delete_account(module, array):
    """Delete Active directory Account"""
    changed = True
    if not module.check_mode:
        res = array.delete_active_directory(
            names=[module.params["name"]], local_only=module.params["local_only"]
        )
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to delete AD Account {0}. Error: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def update_account(module, array):
    """Update existing AD account"""
    changed = False
    current_acc = list(array.get_active_directory(names=[module.params["name"]]).items)[
        0
    ]
    if current_acc.tls != module.params["tls"]:
        changed = True
        if not module.check_mode:
            res = array.patch_active_directory(
                names=[module.params["name"]],
                active_directory=ActiveDirectoryPatch(tls=module.params["tls"]),
            )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to update AD Account {0} TLS setting. Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
    module.exit_json(changed=changed)


def create_account(module, array, api_version):
    """Create Active Directory Account"""
    changed = True
    if LooseVersion(MIN_JOIN_OU_API_VERSION) > LooseVersion(api_version):
        ad_config = ActiveDirectoryPost(
            computer_name=module.params["computer"],
            directory_servers=module.params["directory_servers"],
            kerberos_servers=module.params["kerberos_servers"],
            domain=module.params["domain"],
            user=module.params["username"],
            password=module.params["password"],
        )
    elif LooseVersion(MIN_TLS_API_VERSION) <= LooseVersion(api_version):
        ad_config = ActiveDirectoryPost(
            computer_name=module.params["computer"],
            directory_servers=module.params["directory_servers"],
            kerberos_servers=module.params["kerberos_servers"],
            domain=module.params["domain"],
            user=module.params["username"],
            join_ou=module.params["join_ou"],
            password=module.params["password"],
            tls=module.params["tls"],
        )
    else:
        ad_config = ActiveDirectoryPost(
            computer_name=module.params["computer"],
            directory_servers=module.params["directory_servers"],
            kerberos_servers=module.params["kerberos_servers"],
            domain=module.params["domain"],
            user=module.params["username"],
            join_ou=module.params["join_ou"],
            password=module.params["password"],
        )
    if not module.check_mode:
        if MIN_TLS_API_VERSION in api_version:
            res = array.post_active_directory(
                names=[module.params["name"]],
                join_existing_account=module.params["join_existing"],
                active_directory=ad_config,
            )
        else:
            res = array.post_active_directory(
                names=[module.params["name"]],
                active_directory=ad_config,
            )
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to add Active Directory Account {0}. Error: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            state=dict(type="str", default="present", choices=["absent", "present"]),
            username=dict(type="str"),
            password=dict(type="str", no_log=True),
            name=dict(type="str", required=True),
            computer=dict(type="str"),
            local_only=dict(type="bool", default=False),
            domain=dict(type="str"),
            join_ou=dict(type="str"),
            directory_servers=dict(type="list", elements="str"),
            kerberos_servers=dict(type="list", elements="str"),
            tls=dict(type="str", default="required", choices=["required", "optional"]),
            join_existing=dict(type="bool", default=False),
        )
    )

    required_if = [["state", "present", ["username", "password", "domain"]]]

    module = AnsibleModule(
        argument_spec, required_if=required_if, supports_check_mode=True
    )

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
    exists = bool(
        array.get_active_directory(names=[module.params["name"]]).status_code == 200
    )

    if not module.params["computer"]:
        module.params["computer"] = module.params["name"].replace("_", "-")
    if module.params["kerberos_servers"]:
        if LooseVersion(SERVER_API_VERSION) <= LooseVersion(api_version):
            module.params["kerberos_servers"] = module.params["kerberos_servers"][0:3]
        else:
            module.params["kerberos_servers"] = module.params["kerberos_servers"][0:1]
    if module.params["directory_servers"]:
        if LooseVersion(SERVER_API_VERSION) <= LooseVersion(api_version):
            module.params["directory_servers"] = module.params["directory_servers"][0:3]
        else:
            module.params["directory_servers"] = module.params["directory_servers"][0:1]
    if not exists and state == "present":
        create_account(module, array, api_version)
    elif (
        exists
        and state == "present"
        and LooseVersion(MIN_TLS_API_VERSION) <= LooseVersion(api_version)
    ):
        update_account(module, array)
    elif exists and state == "absent":
        delete_account(module, array)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
