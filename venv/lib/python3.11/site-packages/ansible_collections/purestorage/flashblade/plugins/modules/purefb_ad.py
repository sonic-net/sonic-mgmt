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
module: purefb_ad
version_added: '1.6.0'
short_description: Manage FlashBlade Active Directory Account
description:
- Add or delete FlashBlade Active Directory Account
- FlashBlade allows the creation of one AD computer account, or joining of an
  existing AD computer account.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
    - Name of the AD account
    type: str
    required: true
  existing:
    description:
    - Does the account I(name) already exist in the AD environment
    type: bool
    default: false
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
  encryption:
    description:
    - The encryption types that will be supported for use by clients for Kerberos authentication
    type: list
    elements: str
    choices: [ aes256-sha1, aes128-sha1, arcfour-hmac]
    default: aes256-sha1
  join_ou:
    description:
    - Location where the Computer account will be created. e.g. OU=Arrays,OU=Storage.
    - If left empty, defaults to B(CN=Computers).
    type: str
  directory_servers:
    description:
    - A list of directory servers that will be used for lookups related to user authorization
    - Accepted server formats are IP address and DNS name
    - All specified servers must be registered to the domain appropriately in the array
      configured DNS and will only be communicated with over the secure LDAP (LDAPS) protocol.
      If not specified, servers are resolved for the domain in DNS
    - The specified list can have a maximum length of 5. If more are provided only the first
      5 are used.
    type: list
    elements: str
  kerberos_servers:
    description:
    - A list of key distribution servers to use for Kerberos protocol
    - Accepted server formats are IP address and DNS name
    - All specified servers must be registered to the domain appropriately in the array
      configured DNS. If not specified, servers are resolved for the domain in DNS.
    - The specified list can have a maximum length of 5. If more are provided only the first
      5 are used.
    type: list
    elements: str
  service_principals:
    description:
    - A list of either FQDNs or SPNs for registering services with the domain.
    - If not specified B(Computer Name.Domain) is used
    type: list
    elements: str
  global_catalog_servers:
    description:
    - A list of global catalog servers that will be used for lookups related to user authorization.
    - Accepted server formats are IP address and DNS name with optional @domain suffix.
      If the suffix is ommited, the joined domain is assumed.
    - All specified servers must be registered to the domain appropriately in the arrays
      configured DNS and will only be communicated with over the secure LDAP (LDAPS) protocol.
    type: list
    elements: str
    version_added: 1.20.0
  service:
    description:
    - Service protocol for Active Directory principals
    - Refer to FlashBlade User Guide for more details
    - Use the I(service_principals) parameter instead to correctly define the service type to be used
      for each principal.
    type: list
    elements: str
    choices: ['nfs', 'cifs', 'HOST', '']
    default: ''
  local_only:
    description:
    - Do a local-only delete of an active directory account
    type: bool
    default: false
extends_documentation_fragment:
- purestorage.flashblade.purestorage.fb
"""

EXAMPLES = r"""
- name: Create new AD account
  purestorage.flashblade.purefb_ad:
    name: ad_account
    computer: FLASHBLADE
    domain: acme.com
    username: Administrator
    password: Password
    join_ou: "CN=FakeOU"
    encryption:
    - aes128-cts-hmac-sha1-96
    - aes256-cts-hmac-sha1-96
    kerberos_servers:
    - kdc.acme.com
    directory_servers:
    - ldap.acme.com
    service_principals:
    - "nfs/vip1.flashblade.acme.com"
    - "HOST/vip2.flashblade.acme.com"
    global_catalog_servers:
    - gc1.flashblade.acme.com
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641

- name: Connect to existing AD account
  purestorage.flashblade.purefb_ad:
    name: ad_account
    computer: FLASHBLADE
    domain: acme.com
    username: Administrator
    password: Password
    existing: true
    kerberos_servers:
    - kdc.acme.com
    directory_servers:
    - ldap.acme.com
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641

- name: Update existing AD account
  purestorage.flashblade.purefb_ad:
    name: ad_account
    encryption:
    - aes256-cts-hmac-sha1-96
    kerberos_servers:
    - kdc.acme.com
    directory_servers:
    - ldap.acme.com
    service_principals:
    - "HOST/vip1.flashblade.acme.com"
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641

- name: Delete local AD account
  purestorage.flashblade.purefb_ad:
    name: ad_account
    local_only: true
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641

- name: Fully delete AD account
  purestorage.flashblade.purefb_ad:
    name: ad_account
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641
"""

RETURN = r"""
"""

HAS_PURESTORAGE = True
try:
    from pypureclient.flashblade import ActiveDirectoryPost, ActiveDirectoryPatch
except ImportError:
    HAS_PURESTORAGE = False

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_system,
    purefb_argument_spec,
)

GC_SERVERS_API_VERSION = "2.12"


def delete_account(module, blade):
    """Delete Active directory Account"""
    changed = True
    if not module.check_mode:
        res = blade.delete_active_directory(
            names=[module.params["name"]], local_only=module.params["local_only"]
        )
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to delete AD Account {0}".format(module.params["name"])
            )
    module.exit_json(changed=changed)


def create_account(module, blade):
    """Create Active Directory Account"""
    changed = True
    api_version = list(blade.get_versions().items)
    if not module.params["existing"]:
        if GC_SERVERS_API_VERSION in api_version:
            ad_config = ActiveDirectoryPost(
                computer_name=module.params["computer"],
                directory_servers=module.params["directory_servers"],
                kerberos_servers=module.params["kerberos_servers"],
                domain=module.params["domain"],
                encryption_types=module.params["encryption"],
                fqdns=module.params["service_principals"],
                join_ou=module.params["join_ou"],
                user=module.params["username"],
                password=module.params["password"],
                global_catalog_servers=module.params["global_catalog_servers"],
            )
        else:
            ad_config = ActiveDirectoryPost(
                computer_name=module.params["computer"],
                directory_servers=module.params["directory_servers"],
                kerberos_servers=module.params["kerberos_servers"],
                domain=module.params["domain"],
                encryption_types=module.params["encryption"],
                fqdns=module.params["service_principals"],
                join_ou=module.params["join_ou"],
                user=module.params["username"],
                password=module.params["password"],
            )
        if not module.check_mode:
            res = blade.post_active_directory(
                names=[module.params["name"]], active_directory=ad_config
            )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to add Active Directory Account {0}. Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
    else:
        if GC_SERVERS_API_VERSION in api_version:
            ad_config = ActiveDirectoryPost(
                computer_name=module.params["computer"],
                directory_servers=module.params["directory_servers"],
                kerberos_servers=module.params["kerberos_servers"],
                domain=module.params["domain"],
                encryption_types=module.params["encryption"],
                user=module.params["username"],
                password=module.params["password"],
                global_catalog_servers=module.params["global_catalog_servers"],
            )
        else:
            ad_config = ActiveDirectoryPost(
                computer_name=module.params["computer"],
                directory_servers=module.params["directory_servers"],
                kerberos_servers=module.params["kerberos_servers"],
                domain=module.params["domain"],
                encryption_types=module.params["encryption"],
                user=module.params["username"],
                password=module.params["password"],
            )
        if not module.check_mode:
            res = blade.post_active_directory(
                names=[module.params["name"]],
                active_directory=ad_config,
                join_existing_account=True,
            )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to add Active Directory Account {0}. Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
    module.exit_json(changed=changed)


def update_account(module, blade):
    """Update Active Directory Account"""
    api_version = list(blade.get_versions().items)
    changed = False
    mod_ad = False
    current_ad = list(blade.get_active_directory(names=[module.params["name"]]).items)[
        0
    ]
    attr = {}
    if (
        module.params["join_ou"] != current_ad.join_ou
        and module.params["encryption"].sort() != current_ad.encryption_types.sort()
    ):
        module.fail_json(msg="Cannot make changes to OU when changing encryption types")
    if module.params["directory_servers"]:
        if current_ad.directory_servers:
            if sorted(module.params["directory_servers"]) != sorted(
                current_ad.directory_servers
            ):
                attr["directory_servers"] = module.params["directory_servers"]
                mod_ad = True
    if module.params["kerberos_servers"]:
        if current_ad.kerberos_servers:
            if sorted(module.params["kerberos_servers"]) != sorted(
                current_ad.kerberos_servers
            ):
                attr["kerberos_servers"] = module.params["kerberos_servers"]
                mod_ad = True
    if module.params["join_ou"] != current_ad.join_ou:
        attr["join_ou"] = module.params["join_ou"]
        mod_ad = True
    if sorted(module.params["encryption"]) != sorted(current_ad.encryption_types):
        attr["encryption_types"] = module.params["encryption"]
        mod_ad = True
    if len(module.params["service"]) > 1 or module.params["service"] != "":
        module.warn(
            "Please incorporate the service parameter into the "
            "service_principals parameter for better security control."
        )
    elif module.params["service_principals"]:
        for sprin in range(len(module.params["service_principals"])):
            if "/" not in module.params["service_principals"][sprin]:
                module.params["service_principals"][sprin] = (
                    module.params["service"]
                    + "/"
                    + module.params["service_principals"][sprin]
                )
    if module.params["service_principals"]:
        if current_ad.service_principal_names:
            if sorted(module.params["service_principals"]) != sorted(
                current_ad.service_principal_names
            ):
                attr["service_principal_names"] = module.params["service_principals"]
                mod_ad = True
    if GC_SERVERS_API_VERSION in api_version:
        if module.params["global_catalog_servers"]:
            if current_ad.global_catalog_servers:
                if sorted(current_ad.global_catalog_servers) != sorted(
                    module.params["global_catalog_servers"]
                ):
                    attr["global_catalog_servers"] = module.params[
                        "global_catalog_servers"
                    ]
                    mod_ad = True
    if mod_ad:
        changed = True
        if not module.check_mode:
            ad_attr = ActiveDirectoryPatch(**attr)
            res = blade.patch_active_directory(
                names=[module.params["name"]], active_directory=ad_attr
            )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to update Active Directory Account {0}. Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(
            state=dict(type="str", default="present", choices=["absent", "present"]),
            username=dict(type="str"),
            password=dict(type="str", no_log=True),
            name=dict(type="str", required=True),
            computer=dict(type="str"),
            service=dict(
                type="list",
                elements="str",
                default="",
                choices=["nfs", "cifs", "HOST", ""],
            ),
            existing=dict(type="bool", default=False),
            local_only=dict(type="bool", default=False),
            domain=dict(type="str"),
            join_ou=dict(type="str"),
            directory_servers=dict(type="list", elements="str"),
            kerberos_servers=dict(type="list", elements="str"),
            service_principals=dict(type="list", elements="str"),
            global_catalog_servers=dict(type="list", elements="str"),
            encryption=dict(
                type="list",
                elements="str",
                choices=["aes256-sha1", "aes128-sha1", "arcfour-hmac"],
                default=["aes256-sha1"],
            ),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    if not HAS_PURESTORAGE:
        module.fail_json(msg="py-pure-client sdk is required for this module")

    blade = get_system(module)
    module.params["encryption"] = [
        crypt.replace("aes256-sha1", "aes256-cts-hmac-sha1-96").replace(
            "aes128-sha1", "aes128-cts-hmac-sha1-96"
        )
        for crypt in module.params["encryption"]
    ]
    state = module.params["state"]
    exists = bool(blade.get_active_directory().total_item_count == 1)

    # TODO: Check SMB mode.
    # If mode is SMB adapter only allow nfs
    # Only allow cifs or HOST is SMB mode is native

    if not module.params["computer"]:
        module.params["computer"] = module.params["name"].replace("_", "-")
    if module.params["kerberos_servers"]:
        module.params["kerberos_servers"] = module.params["kerberos_servers"][0:5]
    if module.params["directory_servers"]:
        module.params["directory_servers"] = module.params["directory_servers"][0:5]

    if not exists and state == "present":
        create_account(module, blade)
    elif exists and state == "present":
        update_account(module, blade)
    elif exists and state == "absent":
        delete_account(module, blade)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
