#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Anvitha Jain (@anvjain) <anvjain@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: ndo_macsec_policy
short_description: Manage MACsec Policies on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage MACsec Policies on Cisco Nexus Dashboard Orchestrator (NDO).
- This module is only supported on ND v3.1 (NDO v4.3) and later.
author:
- Anvitha Jain (@anvjain)
options:
  template:
    description:
    - The name of the template.
    - The template must be a fabric policy template.
    type: str
    required: true
  macsec_policy:
    description:
    - The name of the MACsec Policy.
    type: str
    aliases: [ name ]
  macsec_policy_uuid:
    description:
    - The UUID of the MACsec Policy.
    - This parameter is required when the O(macsec_policy) needs to be updated.
    type: str
    aliases: [ uuid ]
  description:
    description:
    - The description of the MACsec Policy.
    type: str
  admin_state:
    description:
    - The administrative state of the MACsec Policy. (Enables or disables the policy)
    - The default value is C(enabled).
    type: str
    choices: [ enabled, disabled ]
  interface_type:
    description:
    - The type of the interfaces this policy will be applied to.
    type: str
    choices: [ fabric, access ]
    default: fabric
  cipher_suite:
    description:
    - The cipher suite to be used for encryption.
    - The default value is C(256_gcm_aes_xpn).
    type: str
    choices: [ 128_gcm_aes, 128_gcm_aes_xpn, 256_gcm_aes, 256_gcm_aes_xpn ]
  window_size:
    description:
    - The window size defines the maximum number of frames that can be received out of order
    - before a replay attack is detected.
    - The value must be between 0 and 4294967295.
    - The default value is 0 for type C(fabric) and 64 for type C(access).
    type: int
  security_policy:
    description:
    - The security policy to allow traffic on the link for the MACsec Policy.
    - The default value is C(should_secure).
    type: str
    choices: [ should_secure, must_secure ]
  sak_expiry_time:
    description:
    - The expiry time for the Security Association Key (SAK) for the MACsec Policy.
    - The value must be 0 or between 60 and 2592000.
    - The default value is 0.
    type: int
  confidentiality_offset:
    description:
    - The confidentiality offset for the MACsec Policy.
    - The default value is 0.
    - This parameter is only available for type C(access).
    type: int
    choices: [ 0, 30, 50 ]
  key_server_priority:
    description:
    - The key server priority for the MACsec Policy.
    - The value must be between 0 and 255.
    - The default value 16 for type C(access).
    - This parameter is only available for type C(access).
    type: int
  macsec_keys:
    description:
    - List of the MACsec Keys.
    - Providing an empty list will remove the O(macsec_keys) from the MACsec Policy.
    - The old O(macsec_keys) entries will be replaced with the new entries during update.
    type: list
    elements: dict
    suboptions:
      key_name:
        description:
        - The name of the MACsec Key.
        - Key Name has to be Hex chars [0-9a-fA-F]
        type: str
        required: true
      psk:
        description:
        - The Pre-Shared Key (PSK) for the MACsec Key.
        - PSK has to be 64 chars long if cipher suite is C(256_gcm_aes) or C(256_gcm_aes_xpn).
        - PSK has to be 32 chars long if cipher suite is C(128_gcm_aes) or C(128_gcm_aes_xpn).
        - PSK has to be Hex chars [0-9a-fA-F]
        type: str
        required: true
      start_time:
        description:
        - The start time for the MACsec Key.
        - The date time format - YYYY-MM-DD HH:MM:SS or 'now'
        - The start time for each key_name should be unique.
        - The default value is C(now).
        type: str
      end_time:
        description:
        - The end time for the MACsec Key.
        - The date time format - YYYY-MM-DD HH:MM:SS or 'infinite'
        - The default value is C(infinite).
        type: str
  state:
    description:
    - Use C(absent) for removing.
    - Use C(query) for listing an object or multiple objects.
    - Use C(present) for creating or updating.
    type: str
    choices: [ absent, query, present ]
    default: query
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Create a new MACsec Policy of interface_type fabric
  cisco.mso.ndo_macsec_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test_template
    macsec_policy: ansible_test_macsec_policy
    description: "Ansible Test MACsec Policy"
    state: present

- name: Create a new MACsec Policy of interface_type access
  cisco.mso.ndo_macsec_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test_template
    macsec_policy: ansible_test_macsec_policy
    description: "Ansible Test MACsec Policy"
    macsec_keys:
      - key_name: ansible_test_key
        psk: 'AA111111111111111111111111111111111111111111111111111111111111aa'
        start_time: '2029-12-11 11:12:13'
        end_time: 'infinite'
    state: present

- name: Query a MACsec Policy with macsec_policy name
  cisco.mso.ndo_macsec_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test_template
    macsec_policy: ansible_test_macsec_policy
    state: query
  register: query_one

- name: Query all MACsec Policies
  cisco.mso.ndo_macsec_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test_template
    state: query
  register: query_all

- name: Query a MACsec Policy with macsec_policy UUID
  cisco.mso.ndo_macsec_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test_template
    macsec_policy_uuid: ansible_test_macsec_policy_uuid
    state: query
  register: query_uuid

- name: Delete a MACsec Policy with name
  cisco.mso.ndo_macsec_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test_template
    macsec_policy: ansible_test_macsec_policy
    state: absent

- name: Delete a MACsec Policy with UUID
  cisco.mso.ndo_macsec_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test_template
    macsec_policy_uuid: ansible_test_macsec_policy_uuid
    state: absent
"""

RETURN = r"""
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec
from ansible_collections.cisco.mso.plugins.module_utils.template import MSOTemplate, KVPair
from ansible_collections.cisco.mso.plugins.module_utils.constants import NDO_CIPHER_SUITE_MAP, NDO_SECURITY_POLICY_MAP
import copy


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        dict(
            template=dict(type="str", required=True),
            macsec_policy=dict(type="str", aliases=["name"]),
            macsec_policy_uuid=dict(type="str", aliases=["uuid"]),
            description=dict(type="str"),
            admin_state=dict(type="str", choices=["enabled", "disabled"]),
            interface_type=dict(type="str", choices=["fabric", "access"], default="fabric"),
            cipher_suite=dict(type="str", choices=list(NDO_CIPHER_SUITE_MAP)),
            window_size=dict(type="int"),
            security_policy=dict(type="str", choices=list(NDO_SECURITY_POLICY_MAP)),
            sak_expiry_time=dict(type="int"),
            confidentiality_offset=dict(type="int", choices=[0, 30, 50]),
            key_server_priority=dict(type="int"),
            macsec_keys=dict(
                type="list",
                elements="dict",
                options=dict(
                    key_name=dict(type="str", required=True),
                    psk=dict(type="str", required=True, no_log=True),
                    start_time=dict(type="str"),
                    end_time=dict(type="str"),
                ),
                no_log=False,
            ),
            state=dict(type="str", choices=["absent", "query", "present"], default="query"),
        )
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "present", ["macsec_policy", "macsec_policy_uuid"], True],
            ["state", "absent", ["macsec_policy", "macsec_policy_uuid"], True],
        ],
    )

    mso = MSOModule(module)

    template = module.params.get("template")
    macsec_policy = module.params.get("macsec_policy")
    macsec_policy_uuid = module.params.get("macsec_policy_uuid")
    description = module.params.get("description")
    admin_state = module.params.get("admin_state")
    interface_type = module.params.get("interface_type")
    cipher_suite = NDO_CIPHER_SUITE_MAP.get(module.params.get("cipher_suite"))
    window_size = module.params.get("window_size")
    security_policy = NDO_SECURITY_POLICY_MAP.get(module.params.get("security_policy"))
    sak_expiry_time = module.params.get("sak_expiry_time")
    confidentiality_offset = module.params.get("confidentiality_offset")
    key_server_priority = module.params.get("key_server_priority")
    macsec_keys = module.params.get("macsec_keys")
    state = module.params.get("state")

    ops = []
    match = None

    mso_template = MSOTemplate(mso, "fabric_policy", template)
    mso_template.validate_template("fabricPolicy")

    path = "/fabricPolicyTemplate/template/macsecPolicies"
    object_description = "MACsec Policy"

    existing_macsec_policies = mso_template.template.get("fabricPolicyTemplate", {}).get("template", {}).get("macsecPolicies", [])
    if macsec_policy or macsec_policy_uuid:
        match = mso_template.get_object_by_key_value_pairs(
            object_description,
            existing_macsec_policies,
            [KVPair("uuid", macsec_policy_uuid) if macsec_policy_uuid else KVPair("name", macsec_policy)],
        )
        if match:
            mso.existing = mso.previous = copy.deepcopy(match.details)
    else:
        mso.existing = mso.previous = existing_macsec_policies

    if state == "present":

        if match:

            if macsec_policy and match.details.get("name") != macsec_policy:
                ops.append(dict(op="replace", path="{0}/{1}/name".format(path, match.index), value=macsec_policy))
                match.details["name"] = macsec_policy

            if description is not None and match.details.get("description") != description:
                ops.append(dict(op="replace", path="{0}/{1}/description".format(path, match.index), value=description))
                match.details["description"] = description

            if admin_state and match.details.get("adminState") != admin_state:
                ops.append(dict(op="replace", path="{0}/{1}/adminState".format(path, match.index), value=admin_state))
                match.details["adminState"] = admin_state

            if interface_type and match.details.get("type") != interface_type:
                mso.fail_json(msg="Type cannot be changed for an existing MACsec Policy.")

            if cipher_suite and match.details.get("macsecParams")["cipherSuite"] != cipher_suite:
                ops.append(dict(op="replace", path="{0}/{1}/macsecParams/cipherSuite".format(path, match.index), value=cipher_suite))
                match.details["macsecParams"]["cipherSuite"] = cipher_suite

            if window_size and match.details.get("macsecParams")["windowSize"] != window_size:
                ops.append(dict(op="replace", path="{0}/{1}/macsecParams/windowSize".format(path, match.index), value=window_size))
                match.details["macsecParams"]["windowSize"] = window_size

            if security_policy and match.details.get("macsecParams")["securityPol"] != security_policy:
                ops.append(dict(op="replace", path="{0}/{1}/macsecParams/securityPol".format(path, match.index), value=security_policy))
                match.details["macsecParams"]["securityPol"] = security_policy

            if sak_expiry_time and match.details.get("macsecParams")["sakExpiryTime"] != sak_expiry_time:
                ops.append(dict(op="replace", path="{0}/{1}/macsecParams/sakExpiryTime".format(path, match.index), value=sak_expiry_time))
                match.details["macsecParams"]["sakExpiryTime"] = sak_expiry_time

            if interface_type == "access":
                if confidentiality_offset and match.details.get("macsecParams")["confOffSet"] != confidentiality_offset:
                    ops.append(
                        dict(op="replace", path="{0}/{1}/macsecParams/confOffSet".format(path, match.index), value="offset{0}".format(confidentiality_offset))
                    )
                    match.details["macsecParams"]["confOffSet"] = "offset{0}".format(confidentiality_offset)

                if key_server_priority and match.details.get("macsecParams")["keyServerPrio"] != key_server_priority:
                    ops.append(dict(op="replace", path="{0}/{1}/macsecParams/keyServerPrio".format(path, match.index), value=key_server_priority))
                    match.details["macsecParams"]["keyServerPrio"] = key_server_priority

            if macsec_keys:
                # updating macsec_keys modifies the existing list with the new list
                macsec_keys_list = []
                for macsec_key in macsec_keys:
                    macsec_keys_list.append(
                        dict(
                            keyname=macsec_key.get("key_name"),
                            psk=macsec_key.get("psk"),
                            start=mso.verify_time_format(macsec_key.get("start_time")) if macsec_key.get("start_time") else None,
                            end=mso.verify_time_format(macsec_key.get("end_time")) if macsec_key.get("end_time") else None,
                        )
                    )

                if macsec_keys_list != match.details.get("macsecKeys", []):
                    ops.append(dict(op="replace", path="{0}/{1}/macsecKeys".format(path, match.index), value=macsec_keys_list))
                match.details["macsecKeys"] = macsec_keys
            elif macsec_keys == []:
                # remove macsec_keys if the list is empty
                ops.append(dict(op="remove", path="{0}/{1}/macsecKeys".format(path, match.index)))
                match.details.pop("macsecKeys", None)

            mso.sanitize(match.details)

        else:
            macsec_param_map = {}

            payload = {"name": macsec_policy, "templateId": mso_template.template.get("templateId"), "schemaId": mso_template.template.get("schemaId")}
            payload["type"] = interface_type

            if description:
                payload["description"] = description
            if admin_state:
                payload["adminState"] = admin_state
            if cipher_suite:
                macsec_param_map["cipherSuite"] = cipher_suite
            if window_size:
                macsec_param_map["windowSize"] = window_size
            if security_policy:
                macsec_param_map["securityPol"] = security_policy
            if sak_expiry_time:
                macsec_param_map["sakExpiryTime"] = sak_expiry_time

            if interface_type == "access":
                if confidentiality_offset:
                    macsec_param_map["confOffSet"] = "offset{0}".format(confidentiality_offset)
                if key_server_priority:
                    macsec_param_map["keyServerPrio"] = key_server_priority
                payload["macsecParams"] = macsec_param_map

            if macsec_keys:
                macsec_keys_list = []
                for macsec_key in macsec_keys:
                    macsec_key_dict = {
                        "keyname": macsec_key.get("key_name"),
                        "psk": macsec_key.get("psk"),
                    }
                    if macsec_key.get("start_time"):
                        macsec_key_dict["start"] = macsec_key.get("start_time")
                    if macsec_key.get("end_time"):
                        macsec_key_dict["end"] = macsec_key.get("end_time")
                    macsec_keys_list.append(macsec_key_dict)
                payload["macsecKeys"] = macsec_keys_list

            ops.append(dict(op="add", path="{0}/-".format(path), value=copy.deepcopy(payload)))

            mso.sanitize(payload)

        mso.existing = mso.proposed

    elif state == "absent":
        if match:
            ops.append(dict(op="remove", path="{0}/{1}".format(path, match.index)))

    if not module.check_mode and ops:
        response = mso.request(mso_template.template_path, method="PATCH", data=ops)
        macsec_policies = response.get("fabricPolicyTemplate", {}).get("template", {}).get("macsecPolicies", [])
        match = mso_template.get_object_by_key_value_pairs(
            object_description,
            macsec_policies,
            [KVPair("uuid", macsec_policy_uuid) if macsec_policy_uuid else KVPair("name", macsec_policy)],
        )
        if match:
            mso.existing = match.details
        else:
            mso.existing = {}
    elif module.check_mode and state != "query":
        mso.existing = mso.proposed if state == "present" else {}

    mso.exit_json()


if __name__ == "__main__":
    main()
