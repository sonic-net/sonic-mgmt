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
module: purefa_ds
version_added: '1.0.0'
short_description: Configure FlashArray Directory Service
description:
- Set or erase configuration for the directory service. There is no facility
  to SSL certificates at this time. Use the FlashArray GUI for this
  additional configuration work.
- To modify an existing directory service configuration you must first delete
  an exisitng configuration and then recreate with new settings.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  state:
    type: str
    description:
    - Create, delete or test directory service configuration
    default: present
    choices: [ absent, present, test ]
  enable:
    description:
    - Whether to enable or disable directory service support.
    default: false
    type: bool
  dstype:
    description:
    - The type of directory service to work on
    choices: [ management, data ]
    type: str
    default: management
  uri:
    type: list
    elements: str
    description:
    - A list of up to 30 URIs of the directory servers. Each URI must include
      the scheme ldap:// or ldaps:// (for LDAP over SSL), a hostname, and a
      domain name or IP address. For example, ldap://ad.company.com configures
      the directory service with the hostname "ad" in the domain "company.com"
      while specifying the unencrypted LDAP protocol.
  base_dn:
    type: str
    description:
    - Sets the base of the Distinguished Name (DN) of the directory service
      groups. The base should consist of only Domain Components (DCs). The
      base_dn will populate with a default value when a URI is entered by
      parsing domain components from the URI. The base DN should specify DC=
      for each domain component and multiple DCs should be separated by commas.
  bind_password:
    type: str
    description:
    - Sets the password of the bind_user user name account.
  force_bind_password:
    type: bool
    default: true
    description:
    - Will force the bind password to be reset even if the bind user password
      is unchanged.
    - If set to I(false) and I(bind_user) is unchanged the password will not
      be reset.
    version_added: 1.14.0
  bind_user:
    type: str
    description:
    - Sets the user name that can be used to bind to and query the directory.
    - For Active Directory, enter the username - often referred to as
      sAMAccountName or User Logon Name - of the account that is used to
      perform directory lookups.
    - For OpenLDAP, enter the full DN of the user.
  user_login:
    type: str
    description:
    - User login attribute in the structure of the configured LDAP servers.
      Typically the attribute field that holds the users unique login name.
      Default value is I(sAMAccountName) for Active Directory or I(uid)
      for all other directory services
  user_object:
    type: str
    description:
    - Value of the object class for a management LDAP user.
      Defaults to I(User) for Active Directory servers, I(posixAccount) or
      I(shadowAccount) for OpenLDAP servers dependent on the group type
      of the server, or person for all other directory servers.
  check_peer:
    type: bool
    description:
    - Whether or not server authenticity is enforced when a certificate
      is provided
    default: false
    version_added: 1.24.0
  certificate:
    type: str
    description:
    - The certificate of the Certificate Authority (CA) that signed the
      certificates of the directory servers, which is used to validate the
      authenticity of the configured servers
    - A valid signed certicate in PEM format (Base64 encoded)
    - Includes the "-----BEGIN CERTIFICATE-----" and "-----END CERTIFICATE-----" lines
    version_added: 1.24.0
  context:
    description:
    - Name of fleet member on which to perform the operation.
    - This requires the array receiving the request is a member of a fleet
      and the context name to be a member of the same fleet.
    type: str
    default: ""
    version_added: '1.39.0'
extends_documentation_fragment:
- purestorage.flasharray.purestorage.fa
"""

EXAMPLES = r"""
- name: Delete existing directory service
  purestorage.flasharray.purefa_ds:
    state: absent
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Update empty directory service (disabled)
  purestorage.flasharray.purefa_ds:
    dstype: management
    uri: "ldap://lab.purestorage.com"
    base_dn: "DC=lab,DC=purestorage,DC=com"
    bind_user: Administrator
    bind_password: password
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Enable existing directory service
  purestorage.flasharray.purefa_ds:
    enable: true
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Disable existing directory service
  purestorage.flasharray.purefa_ds:
    enable: false
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Update empty directory service (enabled)
  purestorage.flasharray.purefa_ds:
    enable: true
    dstype: management
    uri: "ldap://lab.purestorage.com"
    base_dn: "DC=lab,DC=purestorage,DC=com"
    bind_user: Administrator
    bind_password: password
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Upload CA certificate for management DNS and check peer
  purestorage.flasharray.purefa_ds:
    enable: true
    dstype: management
    certificate: "{{lookup('file', 'ca_cert.pem') }}"
    check_peer: true
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
"""

RETURN = r"""
"""

HAS_PURESTORAGE = True
try:
    from pypureclient.flasharray import (
        DirectoryService,
        DirectoryServiceManagement,
    )
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

CONTEXT_VERSION = "2.42"


def delete_ds(module, array):
    """Delete Directory Service"""
    changed = True
    api_version = array.get_rest_version()
    if module.params["dstype"] == "management":
        management = DirectoryServiceManagement(
            user_login_attribute="", user_object_class=""
        )
        directory_service = DirectoryService(
            uris=[""],
            base_dn="",
            bind_user="",
            bind_password="",
            enabled=False,
            services=[module.params["dstype"]],
            management=management,
        )
    else:
        directory_service = DirectoryService(
            uris=[""],
            base_dn="",
            bind_user="",
            bind_password="",
            enabled=False,
            services=[module.params["dstype"]],
        )
    if not module.check_mode:
        if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
            res = array.patch_directory_services(
                names=[module.params["dstype"]],
                directory_service=directory_service,
                context_names=[module.params["context"]],
            )
        else:
            res = array.patch_directory_services(
                names=[module.params["dstype"]], directory_service=directory_service
            )
        if res.status_code != 200:
            module.fail_json(
                msg="Delete {0} Directory Service failed. Error message: {1}".format(
                    module.params["dstype"], res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def update_ds(module, array):
    """Update Directory Service"""
    changed = False
    api_version = array.get_rest_version()
    ds_change = False
    password_required = False
    current_ds = []
    if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
        dirservlist = list(
            array.get_directory_services(context_names=[module.params["context"]]).items
        )
    else:
        dirservlist = list(array.get_directory_services().items)
    for dirs in range(0, len(dirservlist)):
        if dirservlist[dirs].name == module.params["dstype"]:
            current_ds = dirservlist[dirs]
    if module.params["uri"] and current_ds.uris is None:
        password_required = True
    if module.params["uri"] and current_ds.uris != module.params["uri"]:
        uris = module.params["uri"]
        ds_change = True
    else:
        uris = current_ds.uris

    base_dn = getattr(current_ds, "base_dn", "")
    bind_user = getattr(current_ds, "bind_user", "")
    cert = getattr(current_ds, "ca_certificate", None)
    if module.params["base_dn"] and module.params["base_dn"] != base_dn:
        base_dn = module.params["base_dn"]
        ds_change = True
    if module.params["enable"] != current_ds.enabled:
        ds_change = True
        if getattr(current_ds, "bind_password", None) is None:
            password_required = True
    if module.params["bind_user"] is not None:
        if module.params["bind_user"] != bind_user:
            bind_user = module.params["bind_user"]
            password_required = True
            ds_change = True
        elif module.params["force_bind_password"]:
            password_required = True
            ds_change = True
    if module.params["bind_password"] is not None and password_required:
        bind_password = module.params["bind_password"]
        ds_change = True
    if password_required and not module.params["bind_password"]:
        module.fail_json(msg="'bind_password' must be provided for this task")
    if module.params["dstype"] == "management":
        if module.params["certificate"] is not None:
            if cert is None and module.params["certificate"] != "":
                cert = module.params["certificate"]
                ds_change = True
            elif cert is None and module.params["certificate"] == "":
                pass
            elif module.params["certificate"] != cert:
                cert = module.params["certificate"]
                ds_change = True
        if module.params["check_peer"] and not cert:
            module.warn(
                "Cannot check_peer without a CA certificate. Disabling check_peer"
            )
            module.params["check_peer"] = False
        if module.params["check_peer"] != current_ds.check_peer:
            ds_change = True
        user_login = getattr(current_ds.management, "user_login_attribute", "")
        user_object = getattr(current_ds.management, "user_object_class", "")
        if (
            module.params["user_object"] is not None
            and user_object != module.params["user_object"]
        ):
            user_object = module.params["user_object"]
            ds_change = True
        if (
            module.params["user_login"] is not None
            and user_login != module.params["user_login"]
        ):
            user_login = module.params["user_login"]
            ds_change = True
        management = DirectoryServiceManagement(
            user_login_attribute=user_login, user_object_class=user_object
        )
        if password_required:
            directory_service = DirectoryService(
                uris=uris,
                base_dn=base_dn,
                bind_user=bind_user,
                bind_password=bind_password,
                enabled=module.params["enable"],
                services=[module.params["dstype"]],
                management=management,
                check_peer=module.params["check_peer"],
                ca_certificate=cert,
            )
        else:
            directory_service = DirectoryService(
                uris=uris,
                base_dn=base_dn,
                bind_user=bind_user,
                enabled=module.params["enable"],
                services=[module.params["dstype"]],
                management=management,
                check_peer=module.params["check_peer"],
                ca_certificate=cert,
            )
    else:
        if password_required:
            directory_service = DirectoryService(
                uris=uris,
                base_dn=base_dn,
                bind_user=bind_user,
                bind_password=bind_password,
                enabled=module.params["enable"],
                services=[module.params["dstype"]],
            )
        else:
            directory_service = DirectoryService(
                uris=uris,
                base_dn=base_dn,
                bind_user=bind_user,
                enabled=module.params["enable"],
                services=[module.params["dstype"]],
            )
    if ds_change:
        changed = True
        if not module.check_mode:
            if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
                res = array.patch_directory_services(
                    names=[module.params["dstype"]],
                    directory_service=directory_service,
                    context_names=[module.params["context"]],
                )
            else:
                res = array.patch_directory_services(
                    names=[module.params["dstype"]], directory_service=directory_service
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="{0} Directory Service failed. Error message: {1}".format(
                        module.params["dstype"].capitalize(), res.errors[0].message
                    )
                )
    module.exit_json(changed=changed)


def test_ds(module, array):
    """Test directory services configuration"""
    test_response = []
    api_version = array.get_rest_version()
    if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
        response = list(
            array.get_directory_services_test(
                names=[module.params["dstype"]],
                context_names=[module.params["context"]],
            ).items
        )
    else:
        response = list(
            array.get_directory_services_test(names=[module.params["dstype"]]).items
        )
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
    module.exit_json(changed=False, test_response=test_response)


def main():
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            uri=dict(type="list", elements="str"),
            state=dict(
                type="str", default="present", choices=["absent", "present", "test"]
            ),
            enable=dict(type="bool", default=False),
            force_bind_password=dict(type="bool", default=True, no_log=True),
            bind_password=dict(type="str", no_log=True),
            bind_user=dict(type="str"),
            base_dn=dict(type="str"),
            user_login=dict(type="str"),
            user_object=dict(type="str"),
            dstype=dict(
                type="str", default="management", choices=["management", "data"]
            ),
            check_peer=dict(type="bool", default=False),
            certificate=dict(type="str"),
            context=dict(type="str", default=""),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    array = get_array(module)

    if not HAS_PURESTORAGE:
        module.fail_json(msg="py-pure-client sdk is required to for this module")

    state = module.params["state"]
    dirserv = []
    dirservlist = list(array.get_directory_services().items)
    for dirs in range(0, len(dirservlist)):
        if dirservlist[dirs].name == module.params["dstype"]:
            dirserv = dirservlist[dirs]
    if dirserv:
        if state == "absent":
            if dirserv.uris != []:
                delete_ds(module, array)
        elif state == "test":
            test_ds(module, array)
        else:
            update_ds(module, array)
    else:
        module.warn(
            "Direcotry Service of type {0} does not exist. Check FlashArray configuration".format(
                module.params["dstype"]
            )
        )

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
