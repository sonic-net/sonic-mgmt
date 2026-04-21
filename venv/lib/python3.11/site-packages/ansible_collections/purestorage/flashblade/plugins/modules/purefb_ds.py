#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2018, Simon Dodsley (simon@purestorage.com)
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
module: purefb_ds
version_added: '1.0.0'
short_description: Configure FlashBlade Directory Service
description:
- Create, modify or erase directory services configurations. There is no
  facility to SSL certificates at this time. Use the FlashBlade GUI for this
  additional configuration work.
- If updating a directory service and i(bind_password) is provided this
  will always cause a change, even if the password given isn't different from
  the current. This makes this part of the module non-idempotent..
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  state:
    description:
    - Create, delete or test directory service configuration
    default: present
    type: str
    choices: [ absent, present, test ]
  dstype:
    description:
    - The type of directory service to work on
    choices: [ management, nfs, smb ]
    type: str
    required: true
  enable:
    description:
    - Whether to enable or disable directory service support.
    default: false
    type: bool
  uri:
    description:
    - A list of up to 30 URIs of the directory servers. Each URI must include
      the scheme ldap:// or ldaps:// (for LDAP over SSL), a hostname, and a
      domain name or IP address. For example, ldap://ad.company.com configures
      the directory service with the hostname "ad" in the domain "company.com"
      while specifying the unencrypted LDAP protocol.
    type: list
    elements: str
  base_dn:
    description:
    - Sets the base of the Distinguished Name (DN) of the directory service
      groups. The base should consist of only Domain Components (DCs). The
      base_dn will populate with a default value when a URI is entered by
      parsing domain components from the URI. The base DN should specify DC=
      for each domain component and multiple DCs should be separated by commas.
    type: str
  bind_password:
    description:
    - Sets the password of the bind_user user name account.
    type: str
  force_bind_password:
    type: bool
    default: true
    description:
    - Will force the bind password to be reset even if the bind user password
      is unchanged.
    - If set to I(false) and I(bind_user) is unchanged the password will not
      be reset.
    version_added: 1.16.0
  bind_user:
    description:
    - Sets the user name that can be used to bind to and query the directory.
    - For Active Directory, enter the username - often referred to as
      sAMAccountName or User Logon Name - of the account that is used to
      perform directory lookups.
    - For OpenLDAP, enter the full DN of the user.
    type: str
  nis_servers:
    description:
    - A list of up to 30 IP addresses or FQDNs for NIS servers.
    - This cannot be used in conjunction with LDAP configurations.
    type: list
    elements: str
  nis_domain:
    description:
    - The NIS domain to search
    - This cannot be used in conjunction with LDAP configurations.
    type: str
  join_ou:
    description:
      - The optional organizational unit (OU) where the machine account
        for the directory service will be created.
    type: str
extends_documentation_fragment:
- purestorage.flashblade.purestorage.fb
"""

EXAMPLES = r"""
- name: Delete existing management directory service
  purestorage.flashblade.purefb_ds:
    dstype: management
    state: absent
    fb_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Create NFS directory service (disabled)
  purestorage.flashblade.purefb_ds:
    dstype: nfs
    uri: "ldaps://lab.purestorage.com"
    base_dn: "DC=lab,DC=purestorage,DC=com"
    bind_user: Administrator
    bind_password: password
    fb_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Enable existing SMB directory service
  purestorage.flashblade.purefb_ds:
    dstypr: smb
    enable: true
    fb_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Disable existing management directory service
  purestorage.flashblade.purefb_ds:
    dstype: management
    enable: false
    fb_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Create NFS directory service (enabled)
  purestorage.flashblade.purefb_ds:
    dstype: nfs
    enable: true
    uri: "ldaps://lab.purestorage.com"
    base_dn: "DC=lab,DC=purestorage,DC=com"
    bind_user: Administrator
    bind_password: password
    fb_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
"""

RETURN = r"""
"""


NO_SMB_VERSION = "2.16"

HAS_PURITY_FB = True
try:
    from pypureclient.flashblade import DirectoryService
except ImportError:
    HAS_PURITY_FB = False


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_system,
    purefb_argument_spec,
)


def enable_ds(module, blade):
    """Enable Directory Service"""
    changed = True
    if not module.check_mode:
        res = blade.patch_directory_services(
            names=[module.params["dstype"]],
            directory_service=DirectoryService(enabled=True),
        )
        if res.status_code != 200:
            module.fail_json(
                msg="Enable {0} Directory Service failed. Error: {1}".format(
                    module.params["dstype"], res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def disable_ds(module, blade):
    """Disable Directory Service"""
    changed = True
    if not module.check_mode:
        res = blade.patch_directory_services(
            names=[module.params["dstype"]],
            directory_service=DirectoryService(enabled=False),
        )
        if res.status_code != 200:
            module.fail_json(
                msg="Disable {0} Directory Service failed. Error: {1}".format(
                    module.params["dstype"], res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def delete_ds(module, blade):
    """Delete Directory Service"""
    changed = True
    if not module.check_mode:
        res = blade.get_directory_services(names=[module.params["dstype"]])
        if res.status_code != 200:
            module.fail_json(
                msg="Fetch {0} Directory Service failed. Error: {1}".format(
                    module.params["dstype"], res.errors[0].message
                )
            )
        dirserv = list(res.items)[0]
        dir_service = DirectoryService()  # Initialize for pylint
        if module.params["dstype"] == "management":
            if dirserv.uris:
                dir_service = DirectoryService(
                    uris=[""],
                    base_dn="",
                    bind_user="",
                    bind_password="",
                    enabled=False,
                )
            else:
                changed = False
        elif module.params["dstype"] == "smb":
            if dirserv.uris:
                smb_attrs = {"join_ou": ""}
                dir_service = DirectoryService(
                    uris=[""],
                    base_dn="",
                    bind_user="",
                    bind_password="",
                    smb=smb_attrs,
                    enabled=False,
                )
            else:
                changed = False
        elif module.params["dstype"] == "nfs":
            if dirserv.uris:
                dir_service = DirectoryService(
                    uris=[""],
                    base_dn="",
                    bind_user="",
                    bind_password="",
                    enabled=False,
                )
            elif dirserv.nfs.nis_domains:
                nfs_attrs = {"nis_domains": [], "nis_servers": []}
                dir_service = DirectoryService(nfs=nfs_attrs, enabled=False)
            else:
                changed = False
        if changed:
            res = blade.patch_directory_services(
                names=[module.params["dstype"]], directory_service=dir_service
            )
            if res.status_code != 200:
                module.fail_json(
                    msg="Delete {0} Directory Service failed. Error: {1}".format(
                        module.params["dstype"], res.errors[0].message
                    )
                )
    module.exit_json(changed=changed)


def update_ds(module, blade):
    """Update Directory Service"""
    mod_ds = False
    changed = False
    password_required = False
    attr = {}
    res = blade.get_directory_services(names=[module.params["dstype"]])
    if res.status_code != 200:
        module.fail_json(
            msg="Fetch {0} Directory Service failed. Error: {1}".format(
                module.params["dstype"], res.errors[0].message
            )
        )
    ds_now = list(res.items)[0]
    if module.params["dstype"] == "nfs" and module.params["nis_servers"]:
        if sorted(module.params["nis_servers"]) != sorted(
            ds_now.nfs.nis_servers
        ) or module.params["nis_domain"] != "".join(map(str, ds_now.nfs.nis_domains)):
            attr["nfs"] = {
                "nis_domains": [module.params["nis_domain"]],
                "nis_servers": module.params["nis_servers"][0:30],
            }
            mod_ds = True
    else:
        if module.params["uri"]:
            if sorted(module.params["uri"][0:30]) != sorted(ds_now.uris):
                attr["uris"] = module.params["uri"][0:30]
                mod_ds = True
                password_required = True
        if module.params["base_dn"]:
            if module.params["base_dn"] != ds_now.base_dn:
                attr["base_dn"] = module.params["base_dn"]
                mod_ds = True
        if module.params["bind_user"]:
            if module.params["bind_user"] != ds_now.bind_user:
                password_required = True
                attr["bind_user"] = module.params["bind_user"]
                mod_ds = True
            elif module.params["force_bind_password"]:
                password_required = True
                mod_ds = True
        if module.params["enable"]:
            if module.params["enable"] != ds_now.enabled:
                attr["enabled"] = module.params["enable"]
                mod_ds = True
        if password_required:
            if module.params["bind_password"]:
                attr["bind_password"] = module.params["bind_password"]
                mod_ds = True
            else:
                module.fail_json(msg="'bind_password' must be provided for this task")
        if module.params["dstype"] == "smb":
            if module.params["join_ou"] != ds_now.smb.join_ou:
                attr["smb"] = {"join_ou": module.params["join_ou"]}
                mod_ds = True
    if mod_ds:
        changed = True
        if not module.check_mode:
            n_attr = DirectoryService(**attr)
            res = blade.patch_directory_services(
                names=[module.params["dstype"]], directory_service=n_attr
            )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to change {0} directory service. Error: {1}".format(
                        module.params["dstype"], res.errors[0].message
                    )
                )
    module.exit_json(changed=changed)


def create_ds(module, blade):
    """Create Directory Service"""
    changed = True
    if not module.check_mode:
        dir_service = DirectoryService()  # Initialize for pylint
        if module.params["dstype"] == "management":
            if module.params["uri"]:
                dir_service = DirectoryService(
                    uris=module.params["uri"][0:30],
                    base_dn=module.params["base_dn"],
                    bind_user=module.params["bind_user"],
                    bind_password=module.params["bind_password"],
                    enabled=module.params["enable"],
                )
            else:
                module.fail_json(
                    msg="Incorrect parameters provided for dstype {0}".format(
                        module.params["dstype"]
                    )
                )
        elif module.params["dstype"] == "smb":
            if module.params["uri"]:
                smb_attrs = {"join_ou": module.params["join_ou"]}
                dir_service = DirectoryService(
                    uris=module.params["uri"][0:30],
                    base_dn=module.params["base_dn"],
                    bind_user=module.params["bind_user"],
                    bind_password=module.params["bind_password"],
                    smb=smb_attrs,
                    enabled=module.params["enable"],
                )
            else:
                module.fail_json(
                    msg="Incorrect parameters provided for dstype {0}".format(
                        module.params["dstype"]
                    )
                )
        elif module.params["dstype"] == "nfs":
            if module.params["nis_domain"]:
                nfs_attrs = {
                    "nis_domains": [module.params["nis_domain"]],
                    "nis_servers": module.params["nis_servers"][0:30],
                }
                dir_service = DirectoryService(
                    nfs=nfs_attrs, enabled=module.params["enable"]
                )
            else:
                dir_service = DirectoryService(
                    uris=module.params["uri"][0:30],
                    base_dn=module.params["base_dn"],
                    bind_user=module.params["bind_user"],
                    bind_password=module.params["bind_password"],
                    enabled=module.params["enable"],
                )
        res = blade.patch_directory_services(
            names=[module.params["dstype"]], directory_service=dir_service
        )
        if res.status_code != 200:
            module.fail_json(
                msg="Create {0} Directory Service failed. Error: {1}".format(
                    module.params["dstype"], res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def test_ds(module, blade):
    """Test directory services configuration"""
    test_response = []
    response = list(
        blade.get_directory_services_test(names=[module.params["dstype"]]).items
    )
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
    module.exit_json(changed=False, test_response=test_response)


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(
            uri=dict(type="list", elements="str"),
            dstype=dict(
                required=True, type="str", choices=["management", "nfs", "smb"]
            ),
            state=dict(
                type="str", default="present", choices=["absent", "present", "test"]
            ),
            enable=dict(type="bool", default=False),
            bind_password=dict(type="str", no_log=True),
            force_bind_password=dict(type="bool", default=True, no_log=False),
            bind_user=dict(type="str"),
            base_dn=dict(type="str"),
            join_ou=dict(type="str"),
            nis_domain=dict(type="str"),
            nis_servers=dict(type="list", elements="str"),
        )
    )

    required_together = [
        ["uri", "bind_password", "bind_user", "base_dn"],
        ["nis_servers", "nis_domain"],
    ]
    mutually_exclusive = [["uri", "nis_domain"]]

    module = AnsibleModule(
        argument_spec,
        required_together=required_together,
        mutually_exclusive=mutually_exclusive,
        supports_check_mode=True,
    )
    if not HAS_PURITY_FB:
        module.fail_json(msg="py-pure-client sdk is required for this module")

    state = module.params["state"]
    blade = get_system(module)
    api_version = list(blade.get_versions().items)
    if NO_SMB_VERSION in api_version and module.params["dstype"] == "smb":
        module.warn("Directory Service for SMB no longer supported by FlashBlade")
        module.exit_json(changed=False)
    ds_configured = False
    res = blade.get_directory_services(names=[module.params["dstype"]])
    ds_configured = False
    if res.status_code == 200:
        ds_configured = True
    dirserv = list(res.items)[0]
    ds_enabled = dirserv.enabled
    ldap_uri = False
    set_ldap = False
    for uri in range(len(dirserv.uris)):
        if "ldap" in dirserv.uris[uri].lower():
            ldap_uri = True
    if module.params["uri"]:
        for uri in range(len(module.params["uri"])):
            if "ldap" in module.params["uri"][uri].lower():
                set_ldap = True
    if not module.params["uri"] and ldap_uri or module.params["uri"] and set_ldap:
        if module.params["nis_servers"] or module.params["nis_domain"]:
            module.fail_json(
                msg="NIS configuration not supported in an LDAP environment"
            )
    if state == "absent":
        delete_ds(module, blade)
    elif ds_configured and module.params["enable"] and ds_enabled:
        update_ds(module, blade)
    elif ds_configured and not module.params["enable"] and ds_enabled:
        disable_ds(module, blade)
    elif ds_configured and module.params["enable"] and not ds_enabled:
        enable_ds(module, blade)
        # Now we have enabled the DS lets make sure there aren't any new updates...
        update_ds(module, blade)
    elif not ds_configured and state == "present":
        create_ds(module, blade)
    elif state == "test":
        test_ds(module, blade)
    else:
        module.exit_json(changed=False)


if __name__ == "__main__":
    main()
