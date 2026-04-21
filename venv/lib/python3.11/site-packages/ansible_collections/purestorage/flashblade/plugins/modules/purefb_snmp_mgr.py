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
module: purefb_snmp_mgr
version_added: '1.0.0'
short_description: Configure FlashBlade SNMP Managers
description:
- Manage SNMP managers on a Pure Storage FlashBlade.
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
    - Create, delete or test SNMP manager
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
- purestorage.flashblade.purestorage.fb
"""

EXAMPLES = r"""
- name: Delete exisitng SNMP manager
  purestorage.flashblade.purefb_snmp_mgr:
    name: manager1
    state: absent
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Create v2c SNMP manager
  purestorage.flashblade.purefb_snmp_mgr:
    name: manager1
    community: public
    host: 10.21.22.23
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Create v3 SNMP manager
  purestorage.flashblade.purefb_snmp_mgr:
    name: manager2
    version: v3
    auth_protocol: MD5
    auth_passphrase: password
    host: 10.21.22.23
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Update existing SNMP manager
  purestorage.flashblade.purefb_snmp_mgr:
    name: manager1
    community: private
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
"""

RETURN = r"""
"""


HAS_PURITY_FB = True
try:
    from pypureclient.flashblade import SnmpManager, SnmpV2c, SnmpV3
except ImportError:
    HAS_PURITY_FB = False


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_system,
    purefb_argument_spec,
)


def update_manager(module, blade):
    """Update SNMP Manager"""
    changed = False
    res = blade.get_snmp_managers(names=[module.params["name"]])
    mgr = list(blade.get_snmp_managers(names=[module.params["name"]]).items)[0]
    if res.status_code != 200:
        module.fail_json(
            msg="Failed to get configuration for SNMP manager {0}. Error: {1}".format(
                module.params["name"], mgr.errors[0].message
            )
        )
    mgr = list(res.items)[0]
    current_attr = {
        "community": getattr(mgr.v2c, "community", None),
        "notification": mgr.notification,
        "host": mgr.host,
        "version": mgr.version,
        "auth_passphrase": getattr(mgr.v3, "auth_passphrase", None),
        "auth_protocol": getattr(mgr.v3, "auth_protocol", None),
        "privacy_passphrase": getattr(mgr.v3, "privacy_passphrase", None),
        "privacy_protocol": getattr(mgr.v3, "privacy_protocol", None),
        "user": getattr(mgr.v3, "user", None),
    }
    new_attr = {
        "community": module.params["community"],
        "notification": module.params["notification"],
        "host": module.params["host"],
        "version": module.params["version"],
        "auth_passphrase": module.params["auth_passphrase"],
        "auth_protocol": module.params["auth_protocol"],
        "privacy_passphrase": module.params["privacy_passphrase"],
        "privacy_protocol": module.params["privacy_protocol"],
        "user": module.params["user"],
    }
    if current_attr != new_attr:
        changed = True
        if not module.check_mode:
            if new_attr["version"] == "v2c":
                updated_v2c_attrs = SnmpV2c(community=new_attr["community"])
                updated_v2c_manager = SnmpManager(
                    host=new_attr["host"],
                    notification=new_attr["notification"],
                    version="v2c",
                    v2c=updated_v2c_attrs,
                )
                res = blade.patch_snmp_managers(
                    names=[module.params["name"]], snmp_manager=updated_v2c_manager
                )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to update v2c SNMP manager {0}. Error: {1}".format(
                            module.params["name"], res.errors[0].message
                        )
                    )
            else:
                updated_v3_attrs = SnmpV3(
                    auth_protocol=new_attr["auth_protocol"],
                    auth_passphrase=new_attr["auth_passphrase"],
                    privacy_protocol=new_attr["privacy_protocol"],
                    privacy_passphrase=new_attr["privacy_passphrase"],
                    user=new_attr["user"],
                )
                updated_v3_manager = SnmpManager(
                    host=new_attr["host"],
                    notification=new_attr["notification"],
                    version="v3",
                    v3=updated_v3_attrs,
                )
                res = blade.patch_snmp_managers(
                    names=[module.params["name"]], snmp_manager=updated_v3_manager
                )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to update v3 SNMP manager {0}. Error: {1}".format(
                            module.params["name"], res.errors[0].message
                        )
                    )

    module.exit_json(changed=changed)


def delete_manager(module, blade):
    """Delete SNMP Manager"""
    changed = True
    if not module.check_mode:
        res = blade.delete_snmp_managers(names=[module.params["name"]])
        if res.status_code != 200:
            module.fail_json(
                msg="Delete SNMP manager {0} failed. Error: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def create_manager(module, blade):
    """Create SNMP Manager"""
    changed = True
    if not module.check_mode:
        if not module.params["version"]:
            module.fail_json(msg="SNMP version required to create a new manager")
        if module.params["version"] == "v2c":
            v2_attrs = SnmpV2c(community=module.params["community"])
            new_v2_manager = SnmpManager(
                host=module.params["host"],
                notification=module.params["notification"],
                version="v2c",
                v2c=v2_attrs,
            )
            res = blade.post_snmp_managers(
                names=[module.params["name"]], snmp_manager=new_v2_manager
            )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to create v2c SNMP manager {0}. Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
        else:
            v3_attrs = SnmpV3(
                auth_protocol=module.params["auth_protocol"],
                auth_passphrase=module.params["auth_passphrase"],
                privacy_protocol=module.params["privacy_protocol"],
                privacy_passphrase=module.params["privacy_passphrase"],
                user=module.params["user"],
            )
            new_v3_manager = SnmpManager(
                host=module.params["host"],
                notification=module.params["notification"],
                version="v3",
                v3=v3_attrs,
            )
            res = blade.post_snmp_managers(
                names=[module.params["name"]], snmp_manager=new_v3_manager
            )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to create v3 SNMP manager {0}. Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
    module.exit_json(changed=changed)


def test_manager(module, blade):
    """Test SNMP manager configuration"""
    test_response = []
    response = list(blade.get_snmp_managers_test(names=[module.params["name"]]).items)
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
            version=dict(type="str", choices=["v2c", "v3"]),
            community=dict(type="str"),
        )
    )

    required_together = [
        ["auth_passphrase", "auth_protocol"],
        ["privacy_passphrase", "privacy_protocol"],
    ]
    required_if = [
        ["version", "v2c", ["community", "host"]],
        ["version", "v3", ["host", "user"]],
    ]

    module = AnsibleModule(
        argument_spec,
        required_together=required_together,
        required_if=required_if,
        supports_check_mode=True,
    )

    state = module.params["state"]
    blade = get_system(module)

    if not HAS_PURITY_FB:
        module.fail_json(msg="py-pure-client SDK is required for this module")

    mgr_configured = False
    mgrs = list(blade.get_snmp_managers().items)
    for mgr in range(len(mgrs)):
        if mgrs[mgr].name == module.params["name"]:
            mgr_configured = True
            break
    if module.params["version"] == "v3":
        if module.params["auth_passphrase"] and (
            8 > len(module.params["auth_passphrase"]) > 32
        ):
            module.fail_json(msg="auth_password must be between 8 and 32 characters")
        if (
            module.params["privacy_passphrase"]
            and 8 > len(module.params["privacy_passphrase"]) > 63
        ):
            module.fail_json(msg="privacy_password must be between 8 and 63 characters")
    if state == "absent" and mgr_configured:
        delete_manager(module, blade)
    elif mgr_configured and state == "present":
        update_manager(module, blade)
    elif not mgr_configured and state == "present":
        create_manager(module, blade)
    elif state == "test" and mgr_configured:
        test_manager(module, blade)
    elif state == "test" and not mgr_configured:
        module.fail_json(
            msg="SNMP Manager {0} not configured".format(module.params["name"])
        )
    else:
        module.exit_json(changed=False)


if __name__ == "__main__":
    main()
