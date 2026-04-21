#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Gaspard Micol (@gmicol) <gmicol@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: aci_firmware_policy
short_description: Manage firmware policies (firmware:FwP)
description:
- This module creates a firmware policy for firmware groups.
- The compatibility check can be explicitly ignored while assigning the firmware.
options:
    name:
        description:
        - The name of the firmware policy
        type: str
    effective_on_reboot:
        description:
        - A property that indicates if the selected firmware version will be active after reboot.
        - The firmware must be effective on an unplanned reboot before the scheduled maintenance operation.
        type: bool
    ignore_compat:
        description:
        - Check if compatibility checks should be ignored
        type: bool
        aliases: [ ignoreCompat ]
    sr_upgrade:
        description:
        - The SR firware upgrade.
        type: bool
    sr_version:
        description:
        -  The SR version of the firmware associated with this policy.
        type: str
    version:
        description:
        - The version of the firmware associated with this policy.
        - The syntax for this field is n9000-xx.x.
        - if the Full Version is 13.1(1i), the value for this field would be n9000-13.1(1i).
        type: str
    version_check_override:
        description:
        - The version check override.
        - This is a directive to ignore the version check for the next install.
        - The version check, which occurs during a maintenance window, checks to see if the desired version matches the running version.
        - If the versions do not match, the install is performed. If the versions do match, the install is not performed.
        - The version check override is a one-time override that performs the install whether or not the versions match.
        - The APIC defaults to C(untriggered) when unset during creation.
        type: str
        choices: [ trigger, trigger_immediate, triggered, untriggered ]
    description:
        description:
        - Description for the firmware policy.
        type: str
        aliases: [ descr ]
    state:
        description:
        - Use C(present) or C(absent) for adding or removing.
        - Use C(query) for listing an object or multiple objects.
        type: str
        choices: [absent, present, query]
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
  description: More information about the internal APIC class B(firmware:FwP).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
    - Steven Gerhart (@sgerhart)
    - Gaspard Micol (@gmicol)
"""

EXAMPLES = r"""
- name: Create a firmware policy
  cisco.aci.aci_firmware_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: my_firmware_policy
    version: n9000-13.2(1m)
    ignore_compat: false
    state: present
  delegate_to: localhost

- name: Delete a firmware policy
  cisco.aci.aci_firmware_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: my_firmware_policy
    state: absent
  delegate_to: localhost

- name: Query all maintenance policies
  cisco.aci.aci_firmware_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

- name: Query a specific firmware policy
  cisco.aci.aci_firmware_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: my_firmware_policy
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


from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec, aci_owner_spec
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.aci.plugins.module_utils.constants import MATCH_TRIGGER_MAPPING


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        name=dict(type="str"),  # Not required for querying all objects
        description=dict(type="str", aliases=["descr"]),
        version=dict(type="str"),
        effective_on_reboot=dict(type="bool"),
        ignore_compat=dict(type="bool", aliases=["ignoreCompat"]),
        sr_upgrade=dict(type="bool"),
        sr_version=dict(type="str"),
        version_check_override=dict(type="str", choices=list(MATCH_TRIGGER_MAPPING.keys())),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        name_alias=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["name"]],
            ["state", "present", ["name", "version"]],
        ],
    )
    aci = ACIModule(module)

    state = module.params.get("state")
    name = module.params.get("name")
    description = module.params.get("description")
    version = module.params.get("version")
    effective_on_reboot = aci.boolean(module.params.get("effective_on_reboot"), "yes", "no")
    ignore_compat = aci.boolean(module.params.get("ignore_compat"), "yes", "no")
    sr_version = module.params.get("sr_version")
    sr_upgrade = aci.boolean(module.params.get("sr_upgrade"), "yes", "no")
    version_check_override = MATCH_TRIGGER_MAPPING.get(module.params.get("version_check_override"))
    name_alias = module.params.get("name_alias")

    aci.construct_url(
        root_class=dict(
            aci_class="firmwareFwP",
            aci_rn="fabric/fwpol-{0}".format(name),
            target_filter={"name": name},
            module_object=name,
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="firmwareFwP",
            class_config=dict(
                name=name,
                descr=description,
                version=version,
                effectiveOnReboot=effective_on_reboot,
                ignoreCompat=ignore_compat,
                srUpgrade=sr_upgrade,
                srVersion=sr_version,
                versionCheckOverride=version_check_override,
                nameAlias=name_alias,
            ),
        )

        aci.get_diff(aci_class="firmwareFwP")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
