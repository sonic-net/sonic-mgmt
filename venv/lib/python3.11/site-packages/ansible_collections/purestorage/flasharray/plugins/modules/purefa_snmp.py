#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2019, Simon Dodsley (simon@purestorage.com)
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
module: purefa_snmp
version_added: '1.0.0'
short_description: Configure FlashArray SNMP Managers
description:
- Manage SNMP managers on a Pure Storage FlashArray.
- Changing of a named SNMP managers version is not supported.
- This module is not idempotent and will always modify an
  existing SNMP manager due to hidden parameters that cannot
  be compared to the play parameters.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
    - Name of SNMP Manager
    required: true
    type: str
  state:
    description:
    - Create, delete or testSNMP manager
    type: str
    default: present
    choices: [ absent, present, test ]
  auth_passphrase:
    type: str
    description:
    - SNMPv3 only. Passphrase of 8 - 32 characters.
  auth_protocol:
    type: str
    description:
    - SNMP v3 only. Hash algorithm to use
    choices: [ MD5, SHA ]
  community:
    type: str
    description:
    - SNMP v2c only. Manager community ID. Between 1 and 32 characters long.
  host:
    type: str
    description:
    - IPv4 or IPv6 address or FQDN to send trap messages to.
  user:
    type: str
    description:
    - SNMP v3 only. User ID recognized by the specified SNMP manager.
      Must be between 1 and 32 characters.
  version:
    type: str
    description:
    - Version of SNMP protocol to use for the manager.
    choices: [ v2c, v3 ]
    default: v2c
  notification:
    type: str
    description:
    - Action to perform on event.
    default: trap
    choices: [ inform, trap ]
  privacy_passphrase:
    type: str
    description:
    - SNMPv3 only. Passphrase to encrypt SNMP messages.
      Must be between 8 and 63 non-space ASCII characters.
  privacy_protocol:
    type: str
    description:
    - SNMP v3 only. Encryption protocol to use
    choices: [ AES, DES ]
extends_documentation_fragment:
- purestorage.flasharray.purestorage.fa
"""

EXAMPLES = r"""
- name: Delete exisitng SNMP manager
  purestorage.flasharray.purefa_snmp:
    name: manager1
    state: absent
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
- name: Create v2c SNMP manager
  puretorage.flasharray.purefa_snmp:
    name: manager1
    community: public
    host: 10.21.22.23
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
- name: Create v3 SNMP manager
  puretorage.flasharray.purefa_snmp:
    name: manager2
    version: v3
    user: manager
    auth_protocol: MD5
    auth_passphrase: password
    host: 10.21.22.23
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
- name: Update existing SNMP manager
  purestorage.flasharray.purefa_snmp:
    name: manager1
    community: private
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
"""

RETURN = r"""
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flasharray.plugins.module_utils.purefa import (
    get_array,
    purefa_argument_spec,
)

HAS_PURESTORAGE = True
try:
    from pypureclient.flasharray import (
        SnmpManagerPost,
        SnmpManagerPatch,
        SnmpV2c,
        SnmpV3Patch,
        SnmpV3Post,
    )
except ImportError:
    HAS_PURESTORAGE = False


def test_manager(module, array):
    """Test SNMP manager configuration"""
    test_response = []
    response = list(array.get_snmp_managers_test(names=[module.params["name"]]).items)
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


def update_manager(module, array):
    """Update SNMP Manager"""
    changed = False
    res = array.get_snmp_managers(names=module.params["name"])
    if res.status_code != 200:
        module.fail_json(
            msg="Failed to get configuration for SNMP manager {0}.".format(
                module.params["name"]
            )
        )
    else:
        mgr = list(res.items)[0]
    if mgr.version != module.params["version"]:
        module.fail_json(msg="Changing an SNMP managers version is not supported.")
    elif module.params["version"] == "v2c":
        changed = True
        if not module.check_mode:
            res = array.patch_snmp_managers(
                names=module.params["name"],
                snmp_manager=SnmpManagerPatch(
                    version=module.params["version"],
                    v2c=SnmpV2c(community=module.params["community"]),
                    notification=module.params["notification"],
                    host=module.params["host"],
                ),
            )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to update SNMP manager {0}. Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
    else:
        if module.params["auth_protocol"] and module.params["privacy_protocol"]:
            changed = True
            if not module.check_mode:
                res = array.patch_snmp_managers(
                    names=module.params["name"],
                    snmp_manager=SnmpManagerPatch(
                        version=module.params["version"],
                        v3=SnmpV3Patch(
                            auth_passphrase=module.params["auth_passphrase"],
                            auth_protocol=module.params["auth_protocol"],
                            privacy_passphrase=module.params["privacy_passphrase"],
                            privacy_protocol=module.params["privacy_protocol"],
                            user=module.params["user"],
                        ),
                        notification=module.params["notification"],
                        host=module.params["host"],
                    ),
                )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to update SNMP manager {0}. Error: {1}".format(
                            module.params["name"], res.errors[0].message
                        )
                    )
        elif module.params["auth_protocol"] and not module.params["privacy_protocol"]:
            changed = True
            if not module.check_mode:
                res = array.patch_snmp_managers(
                    names=module.params["name"],
                    snmp_manager=SnmpManagerPatch(
                        notification=module.params["notification"],
                        version=module.params["version"],
                        host=module.params["host"],
                        v3=SnmpV3Patch(
                            auth_passphrase=module.params["auth_passphrase"],
                            auth_protocol=module.params["auth_protocol"],
                            user=module.params["user"],
                        ),
                    ),
                )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to update SNMP manager {0}. Error: {1}".format(
                            module.params["name"], res.errors[0].message
                        )
                    )
        elif not module.params["auth_protocol"] and module.params["privacy_protocol"]:
            changed = True
            if not module.check_mode:
                res = array.patch_snmp_managers(
                    names=module.params["name"],
                    snmp_manager=SnmpManagerPatch(
                        notification=module.params["notification"],
                        version=module.params["version"],
                        host=module.params["host"],
                        v3=SnmpV3Patch(
                            privacy_passphrase=module.params["privacy_passphrase"],
                            privacy_protocol=module.params["privacy_protocol"],
                            user=module.params["user"],
                        ),
                    ),
                )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to update SNMP manager {0}. Error: {1}".format(
                            module.params["name"], res.errors[0].message
                        )
                    )
        elif (
            not module.params["auth_protocol"] and not module.params["privacy_protocol"]
        ):
            changed = True
            if not module.check_mode:
                res = array.patch_snmp_managers(
                    names=module.params["name"],
                    snmp_manager=SnmpManagerPatch(
                        version=module.params["version"],
                        notification=module.params["notification"],
                        host=module.params["host"],
                        v3=SnmpV3Patch(user=module.params["user"]),
                    ),
                )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to update SNMP manager {0}. Error: {1}".format(
                            module.params["name"], res.errors[0].name
                        )
                    )
        else:
            module.fail_json(
                msg="Invalid parameters selected in update. Please raise issue in Ansible GitHub"
            )

    module.exit_json(changed=changed)


def delete_manager(module, array):
    """Delete SNMP Manager"""
    changed = True
    if not module.check_mode:
        res = array.delete_snmp_managers(names=[module.params["name"]])
        if res.status_code != 200:
            module.fail_json(
                msg="Delete SNMP manager {0} failed. Error: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def create_manager(module, array):
    """Create SNMP Manager"""
    changed = True
    if not module.check_mode:
        if module.params["version"] == "v2c":
            res = array.post_snmp_managers(
                names=module.params["name"],
                snmp_manager=SnmpManagerPost(
                    version=module.params["version"],
                    notification=module.params["notification"],
                    host=module.params["host"],
                    v2c=SnmpV2c(
                        community=module.params["community"],
                    ),
                ),
            )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to create SNMP manager {0}. Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
        else:
            if module.params["auth_protocol"] and module.params["privacy_protocol"]:
                res = array.post_snmp_managers(
                    names=module.params["name"],
                    snmp_manager=SnmpManagerPost(
                        host=module.params["host"],
                        notification=module.params["notification"],
                        version=module.params["version"],
                        v3=SnmpV3Post(
                            auth_passphrase=module.params["auth_passphrase"],
                            auth_protocol=module.params["auth_protocol"],
                            privacy_passphrase=module.params["privacy_passphrase"],
                            privacy_protocol=module.params["privacy_protocol"],
                            user=module.params["user"],
                        ),
                    ),
                )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to create SNMP manager {0}. Error: {1}".format(
                            module.params["name"], res.errors[0].message
                        )
                    )
            elif (
                module.params["auth_protocol"] and not module.params["privacy_protocol"]
            ):
                res = array.post_snmp_managers(
                    names=module.params["name"],
                    snmp_manager=SnmpManagerPost(
                        version=module.params["version"],
                        notification=module.params["notification"],
                        host=module.params["host"],
                        v3=SnmpV3Post(
                            auth_passphrase=module.params["auth_passphrase"],
                            auth_protocol=module.params["auth_protocol"],
                            user=module.params["user"],
                        ),
                    ),
                )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to create SNMP manager {0}. Error: {1}".format(
                            module.params["name"], res.errors[0].message
                        )
                    )
            elif (
                not module.params["auth_protocol"] and module.params["privacy_protocol"]
            ):
                res = array.post_snmp_managers(
                    names=module.params["name"],
                    host=module.params["host"],
                    snmp_managers=SnmpManagerPost(
                        notification=module.params["notification"],
                        version=module.params["version"],
                        v3=SnmpV3Post(
                            privacy_passphrase=module.params["privacy_passphrase"],
                            privacy_protocol=module.params["privacy_protocol"],
                            user=module.params["user"],
                        ),
                    ),
                )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to create SNMP manager {0}. Error: {1}".format(
                            module.params["name"], res.errors[0].message
                        )
                    )
            elif (
                not module.params["auth_protocol"]
                and not module.params["privacy_protocol"]
            ):
                res = array.post_snmp_managers(
                    names=module.params["name"],
                    host=module.params["host"],
                    snmp_manager=SnmpManagerPost(
                        notification=module.params["notification"],
                        version=module.params["version"],
                        v3=SnmpV3Post(
                            user=module.params["user"],
                        ),
                    ),
                )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to create SNMP manager {0}. Error: {1}".format(
                            module.params["name"], res.errors[0].message
                        )
                    )
            else:
                module.fail_json(
                    msg="Invalid parameters selected in create. Please raise issue in Ansible GitHub"
                )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type="str", required=True),
            host=dict(type="str"),
            state=dict(
                type="str", default="present", choices=["absent", "present", "test"]
            ),
            user=dict(type="str"),
            notification=dict(type="str", choices=["inform", "trap"], default="trap"),
            auth_passphrase=dict(type="str", no_log=True),
            auth_protocol=dict(type="str", choices=["MD5", "SHA"]),
            privacy_passphrase=dict(type="str", no_log=True),
            privacy_protocol=dict(type="str", choices=["AES", "DES"]),
            version=dict(type="str", default="v2c", choices=["v2c", "v3"]),
            community=dict(type="str"),
        )
    )

    required_together = [
        ["auth_passphrase", "auth_protocol"],
        ["privacy_passphrase", "privacy_protocol"],
    ]

    module = AnsibleModule(
        argument_spec,
        required_together=required_together,
        supports_check_mode=True,
    )

    if not HAS_PURESTORAGE:
        module.fail_json(msg="py-pure-client sdk is required for this module")

    state = module.params["state"]
    array = get_array(module)
    mgr_configured = False
    mgrs = list(array.get_snmp_managers().items)
    for mgr in range(0, len(mgrs)):
        if mgrs[mgr].name == module.params["name"]:
            mgr_configured = True
            break
    if not module.params["host"]:
        module.fail_json(msg="The following parameter is required: host")
    if module.params["version"] == "v3":
        if not module.params["user"]:
            module.fail_json(msg="version is v3 but the following is missing: user")
        if module.params["auth_passphrase"] and (
            8 > len(module.params["auth_passphrase"]) > 32
        ):
            module.fail_json(msg="auth_password must be between 8 and 32 characters")
        if (
            module.params["privacy_passphrase"]
            and 8 > len(module.params["privacy_passphrase"]) > 63
        ):
            module.fail_json(msg="privacy_password must be between 8 and 63 characters")
    else:
        if not module.params["community"]:
            module.fail_json(
                msg="version is v2c but the following is missing: community"
            )
    if state == "absent" and mgr_configured:
        delete_manager(module, array)
    elif mgr_configured and state == "present":
        update_manager(module, array)
    elif mgr_configured and state == "test":
        test_manager(module, array)
    elif not mgr_configured and state == "present":
        create_manager(module, array)
    else:
        module.exit_json(changed=False)


if __name__ == "__main__":
    main()
