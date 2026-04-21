#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Akini Ross (@akinross) <akinross@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_aaa_security_default_settings
short_description: Manage AAA Key Rings (pki:Ep)
description:
- Manage AAA Key Rings on Cisco ACI fabrics.
options:
  password_strength_check:
    description:
    - Enable password strength check.
    - Use C(true) to enable and C(false) to disable.
    - The APIC defaults to C(true) when unset during creation.
    type: bool
  password_strength_profile:
    description:
    - The password strength profile (aaa:PwdStrengthProfile).
    type: dict
    suboptions:
      enable:
        description:
        - Enable or disable password strength profile.
        - Use C(true) to enable and C(false) to disable.
        type: bool
        required: true
      type:
        description:
        - The type of the password strength profile.
        - The APIC defaults to C(any_three) when unset during creation.
        type: str
        choices: [ custom, any_three ]
      min_length:
        description:
        - The minimum length of the password.
        - The APIC defaults to C(8) when unset during creation.
        type: int
        aliases: [ minimum_length, min ]
      max_length:
        description:
        - The maximum length of the password.
        - The APIC defaults to C(64) when unset during creation.
        type: int
        aliases: [ maximum_length, max ]
      class_flags:
        description:
        - The class flags of the password strength profile.
        - At least 3 class flags must be specified.
        - This attribute is only applicable when type is set to O(password_strength_profile.type=custom).
        - The APIC defaults to C(digits,lowercase,uppercase) when unset during creation.
        type: list
        elements: str
        choices: [ digits, lowercase, specialchars, uppercase ]
        aliases: [ flags ]
  password_change:
    description:
    - The password change interval (aaa:PwdProfile).
    type: dict
    suboptions:
      enable:
        description:
        - Enforce password change interval.
        - Use C(true) to enable and C(false) to disable.
        - The APIC defaults to C(true) when unset during creation.
        type: bool
      interval:
        description:
        - The password change interval in hours.
        - The APIC defaults to C(48) when unset during creation.
        type: int
      allowed_changes:
        description:
        - The number of changes allowed within the change interval.
        - The APIC defaults to C(2) when unset during creation.
        type: int
      minimum_period:
        description:
        - The minimum period between password changes in hours.
        - The APIC defaults to C(24) when unset during creation.
        type: int
        aliases: [ minimum_period_between_password_changes, min_period ]
      history_storage_amount:
        description:
        - The number of recent user passwords to store.
        - The APIC defaults to C(5) when unset during creation.
        type: int
        aliases: [ history, amount ]
  lockout:
    description:
    - Lockout behaviour after multiple failed login attempts (aaa:BlockLoginProfile).
    type: dict
    suboptions:
      enable:
        description:
        - Enable lockout behaviour.
        - Use C(true) to enable and C(false) to disable.
        - The APIC defaults to C(false) when unset during creation.
        type: bool
      max_attempts:
        description:
        - The maximum number of failed attempts before user is locked out.
        - The APIC defaults to C(5) when unset during creation.
        type: int
        aliases: [ max_failed_attempts, failed_attempts, attempts ]
      window:
        description:
        - The time period in which consecutive attempts were failed in minutes.
        - The APIC defaults to C(5) when unset during creation.
        type: int
        aliases: [ max_failed_attempts_window, failed_attempts_window ]
      duration:
        description:
        - The duration of lockout in minutes.
        - The APIC defaults to C(60) when unset during creation.
        type: int
  web_token:
    description:
    - The web token related configuration (pki:WebTokenData).
    type: dict
    suboptions:
      timeout:
        description:
        - The web token timeout in seconds.
        - The APIC defaults to C(600) when unset during creation.
        type: int
      idle_timeout:
        description:
        - The web/console (SSH/Telnet) session idle timeout in seconds.
        - The APIC defaults to C(1200) when unset during creation.
        type: int
        aliases: [ session_idle_timeout ]
      validity_period:
        description:
        - The maximum validity period in hours.
        - The APIC defaults to C(24) when unset during creation.
        type: int
        aliases: [ maximum_validity_period ]
      refresh:
        description:
        - Include refresh in session records.
        - Use C(true) to include and C(false) to exclude.
        - The APIC defaults to C(false) when unset during creation.
        type: bool
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ present, query ]
    default: present
  name_alias:
    description:
    - The alias for the current object. This relates to the nameAlias field in ACI.
    type: str
extends_documentation_fragment:
- cisco.aci.aci
- cisco.aci.annotation
- cisco.aci.owner

seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(pki:Ep).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Akini Ross (@akinross)
"""

EXAMPLES = r"""
- name: Set AAA Security Default Settings
  cisco.aci.aci_aaa_security_default_settings:
    host: apic
    username: admin
    password: SomeSecretPassword
    password_strength_check: true
    password_strength_profile:
      enable: true
      type: custom
      min_length: 10
      max_length: 60
      class_flags:
        - digits
        - lowercase
        - specialchars
        - uppercase
    password_change:
      enable: true
      interval: 49
      allowed_changes: 6
      minimum_period_between_password_changes: 25
      history_storage_amount: 6
    lockout:
      enable: true
      max_attempts: 6
      window: 6
      duration: 61
    web_token:
      timeout: 601
      idle_timeout: 1201
      validity_period: 23
      refresh: true
    state: present
  delegate_to: localhost

- name: Set AAA Security Default Settings to Default Values
  cisco.aci.aci_aaa_security_default_settings:
    host: apic
    username: admin
    password: SomeSecretPassword
    password_strength_check: true
    password_strength_profile:
      enable: false
    password_change:
      enable: true
      interval: 48
      allowed_changes: 2
      minimum_period_between_password_changes: 24
      history_storage_amount: 5
    lockout:
      enable: false
      max_attempts: 5
      window: 5
      duration: 60
    web_token:
      timeout: 600
      idle_timeout: 1200
      validity_period: 24
      refresh: false
    state: present
  delegate_to: localhost

- name: Query AAA Security Default Settings
  cisco.aci.aci_aaa_security_default_settings:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result
"""

RETURN = r"""
current:
  description: The existing configuration from the APIC after the module has finished
  returned: success
  type: list
  sample:
    [
        {
            "fvTenant": {
                "attributes": {
                    "descr": "Production environment",
                    "dn": "uni/tn-production",
                    "name": "production",
                    "nameAlias": "",
                    "ownerKey": "",
                    "ownerTag": ""
                }
            }
        }
    ]
error:
  description: The error information as returned from the APIC
  returned: failure
  type: dict
  sample:
    {
        "code": "122",
        "text": "unknown managed object class foo"
    }
raw:
  description: The raw output returned by the APIC REST API (xml or json)
  returned: parse error
  type: str
  sample: '<?xml version="1.0" encoding="UTF-8"?><imdata totalCount="1"><error code="122" text="unknown managed object class foo"/></imdata>'
sent:
  description: The actual/minimal configuration pushed to the APIC
  returned: info
  type: list
  sample:
    {
        "fvTenant": {
            "attributes": {
                "descr": "Production environment"
            }
        }
    }
previous:
  description: The original configuration from the APIC before the module has started
  returned: info
  type: list
  sample:
    [
        {
            "fvTenant": {
                "attributes": {
                    "descr": "Production",
                    "dn": "uni/tn-production",
                    "name": "production",
                    "nameAlias": "",
                    "ownerKey": "",
                    "ownerTag": ""
                }
            }
        }
    ]
proposed:
  description: The assembled configuration from the user-provided parameters
  returned: info
  type: dict
  sample:
    {
        "fvTenant": {
            "attributes": {
                "descr": "Production environment",
                "name": "production"
            }
        }
    }
filter_string:
  description: The filter string used for the request
  returned: failure or debug
  type: str
  sample: ?rsp-prop-include=config-only
method:
  description: The HTTP method used for the request to the APIC
  returned: failure or debug
  type: str
  sample: POST
response:
  description: The HTTP response from the APIC
  returned: failure or debug
  type: str
  sample: OK (30 bytes)
status:
  description: The HTTP status from the APIC
  returned: failure or debug
  type: int
  sample: 200
url:
  description: The HTTP url used for the request to the APIC
  returned: failure or debug
  type: str
  sample: https://10.11.12.13/api/mo/uni/tn-production.json
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec, aci_owner_spec


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        password_strength_check=dict(type="bool", no_log=False),
        password_strength_profile=dict(
            type="dict",
            no_log=False,
            options=dict(
                enable=dict(type="bool", required=True),
                type=dict(type="str", choices=["custom", "any_three"]),
                min_length=dict(type="int", aliases=["minimum_length", "min"]),
                max_length=dict(type="int", aliases=["maximum_length", "max"]),
                class_flags=dict(type="list", elements="str", choices=["digits", "lowercase", "specialchars", "uppercase"], aliases=["flags"]),
            ),
        ),
        password_change=dict(
            type="dict",
            no_log=False,
            options=dict(
                enable=dict(type="bool"),
                interval=dict(type="int"),
                allowed_changes=dict(type="int"),
                minimum_period=dict(type="int", aliases=["minimum_period_between_password_changes", "min_period"]),
                history_storage_amount=dict(type="int", aliases=["history", "amount"]),
            ),
        ),
        lockout=dict(
            type="dict",
            options=dict(
                enable=dict(type="bool"),
                max_attempts=dict(type="int", aliases=["max_failed_attempts", "failed_attempts", "attempts"]),
                window=dict(type="int", aliases=["max_failed_attempts_window", "failed_attempts_window"]),
                duration=dict(type="int"),
            ),
        ),
        web_token=dict(
            type="dict",
            no_log=False,
            options=dict(
                timeout=dict(type="int"),
                idle_timeout=dict(type="int", aliases=["session_idle_timeout"]),
                validity_period=dict(type="int", aliases=["maximum_validity_period"]),
                refresh=dict(type="bool"),
            ),
        ),
        state=dict(type="str", default="present", choices=["present", "query"]),
        name_alias=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )
    aci = ACIModule(module)

    password_strength_check = aci.boolean(module.params.get("password_strength_check"))
    password_strength_profile = module.params.get("password_strength_profile")
    password_change = module.params.get("password_change")
    lockout = module.params.get("lockout")
    web_token = module.params.get("web_token")
    state = module.params.get("state")
    name_alias = module.params.get("name_alias")

    aci_class = "aaaUserEp"
    child_classes = ["aaaPwdStrengthProfile", "aaaPwdProfile", "aaaBlockLoginProfile", "pkiWebTokenData"]

    aci.construct_url(
        root_class=dict(
            aci_class=aci_class,
            aci_rn="userext",
        ),
        child_classes=child_classes,
    )
    aci.get_existing()

    if state == "present":
        child_configs = []

        class_config = dict(
            pwdStrengthCheck=password_strength_check,
            nameAlias=name_alias,
        )

        if password_strength_profile:
            if password_strength_profile.get("enable"):
                child_configs.append(
                    dict(
                        aaaPwdStrengthProfile=dict(
                            attributes=dict(
                                pwdStrengthTestType=password_strength_profile.get("type"),
                                pwdMinLength=password_strength_profile.get("min_length"),
                                pwdMaxLength=password_strength_profile.get("max_length"),
                                pwdClassFlags=",".join(sorted(password_strength_profile.get("class_flags"))),
                            ),
                        ),
                    ),
                )
            # Delete existing aaaPwdStrengthProfile if enable is set to false and it exists
            # This is done for setting the correct output for changed state
            elif len(aci.existing) > 0 and len(aci.existing[0].get("aaaUserEp", {}).get("children", {})) > 3:
                for child in aci.existing[0].get("aaaUserEp", {}).get("children", {}):
                    if "aaaPwdStrengthProfile" in child.keys():
                        child_configs.append(dict(aaaPwdStrengthProfile=dict(attributes=dict(status="deleted"))))
                        break

        if password_change:
            child_configs.append(
                dict(
                    aaaPwdProfile=dict(
                        attributes=dict(
                            changeDuringInterval=aci.boolean(password_change.get("enable"), "enable", "disable"),
                            changeInterval=password_change.get("interval"),
                            changeCount=password_change.get("allowed_changes"),
                            noChangeInterval=password_change.get("minimum_period"),
                            historyCount=password_change.get("history_storage_amount"),
                        ),
                    ),
                ),
            )

        if lockout:
            child_configs.append(
                dict(
                    aaaBlockLoginProfile=dict(
                        attributes=dict(
                            enableLoginBlock=aci.boolean(lockout.get("enable"), "enable", "disable"),
                            maxFailedAttempts=lockout.get("max_attempts"),
                            maxFailedAttemptsWindow=lockout.get("window"),
                            blockDuration=lockout.get("duration"),
                        ),
                    ),
                ),
            )

        if web_token:
            child_configs.append(
                dict(
                    pkiEp=dict(
                        attributes=dict(descr=""),
                        children=[
                            dict(
                                pkiWebTokenData=dict(
                                    attributes=dict(
                                        webtokenTimeoutSeconds=web_token.get("timeout"),
                                        uiIdleTimeoutSeconds=web_token.get("idle_timeout"),
                                        maximumValidityPeriod=web_token.get("validity_period"),
                                        sessionRecordFlags="login,logout,refresh" if web_token.get("refresh") else "login,logout",
                                    ),
                                ),
                            ),
                        ],
                    ),
                ),
            )

        aci.payload(
            aci_class=aci_class,
            class_config=class_config,
            child_configs=child_configs,
        )

        aci.get_diff(aci_class=aci_class)

        aci.post_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
