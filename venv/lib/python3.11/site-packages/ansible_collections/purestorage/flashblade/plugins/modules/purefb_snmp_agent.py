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
module: purefb_snmp_agent
version_added: '1.0.0'
short_description: Configure the FlashBlade SNMP Agent
description:
- Configure the management SNMP Agent on a Pure Storage FlashBlade.
- This module is not idempotent and will always modify the
  existing management SNMP agent due to hidden parameters that cannot
  be compared to the play parameters.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
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
  user:
    type: str
    description:
    - SNMP v3 only. User ID recognized by the specified SNMP agent.
      Must be between 1 and 32 characters.
  version:
    type: str
    description:
    - Version of SNMP protocol to use for the agent.
    choices: [ v2c, v3 ]
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
- name: Update v2c SNMP agent
  purestorage.flashblade.purefb_snmp_agent:
    community: public
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Update v3 SNMP agent
  purestorage.flashblade.purefb_snmp_agent:
    version: v3
    auth_protocol: MD5
    auth_passphrase: password
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
"""

RETURN = r"""
"""


HAS_PURITY_FB = True
try:
    from pypureclient.flashblade import SnmpAgent, SnmpV2c, SnmpV3
except ImportError:
    HAS_PURITY_FB = False


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_system,
    purefb_argument_spec,
)


def update_agent(module, blade):
    """Update SNMP Agent"""
    changed = False
    res = blade.get_snmp_agents()
    if res.status_code != 200:
        module.fail_json(msg="Failed to get configuration for SNMP agent.")
    agent = list(res.items)[0]
    current_attr = {
        "community": agent.v2c.community,
        "version": agent.version,
        "auth_passphrase": agent.v3.auth_passphrase,
        "auth_protocol": agent.v3.auth_protocol,
        "privacy_passphrase": agent.v3.privacy_passphrase,
        "privacy_protocol": agent.v3.privacy_protocol,
        "user": agent.v3.user,
    }
    new_attr = {
        "community": module.params["community"],
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
                updated_v2c_agent = SnmpAgent(version="v2c", v2c=updated_v2c_attrs)
                res = blade.patch_snmp_agents(snmp_agent=updated_v2c_agent)
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to update v2c SNMP agent. Error: {0}".format(
                            res.errors[0].message
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
                updated_v3_agent = SnmpAgent(version="v3", v3=updated_v3_attrs)
                res = blade.patch_snmp_agents(snmp_agent=updated_v3_agent)
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to update v3 SNMP agent. Error: {0}".format(
                            res.errors[0].message
                        )
                    )

    module.exit_json(changed=changed)


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(
            user=dict(type="str"),
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
    required_if = [["version", "v2c", ["community"]], ["version", "v3", ["user"]]]

    module = AnsibleModule(
        argument_spec,
        required_together=required_together,
        required_if=required_if,
        supports_check_mode=True,
    )

    blade = get_system(module)

    if not HAS_PURITY_FB:
        module.fail_json(msg="py-pure-client SDK is required for this module")

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

    update_agent(module, blade)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
