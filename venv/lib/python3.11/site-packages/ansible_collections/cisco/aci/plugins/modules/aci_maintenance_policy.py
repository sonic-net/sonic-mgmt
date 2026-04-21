#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Gaspard Micol (@gmicol) <gmicol@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: aci_maintenance_policy
short_description: Manage firmware maintenance policies (maint:MaintP)
description:
- Manage maintenance policies that defines behavior during an ACI upgrade.
options:
  name:
    description:
    - The name for the maintenance policy.
    type: str
    aliases: [ maintenance_policy ]
  run_mode:
    description:
    - Whether the system pauses on error or just continues through it.
    - The APIC defaults to C(pauseOnlyOnFailures) when unset during creation.
    type: str
    choices: [ pause_always_between_sets, pause_only_on_failures, pause_never, pauseOnlyOnFailures, pauseNever ]
    aliases: [ runmode ]
  graceful:
    description:
    - Whether the system will bring down the nodes gracefully during an upgrade, which reduces traffic lost.
    - The APIC defaults to C(false) when unset during creation.
    type: bool
  scheduler:
    description:
    - The name of scheduler that is applied to the policy.
    type: str
  admin_state:
    description:
    - The administrative state of the executable policies.
    - Will trigger an immediate upgrade for nodes if C(admin_state) is set to triggered.
    - The APIC defaults to C(untriggered) when unset during creation.
    type: str
    choices: [ triggered, untriggered ]
    aliases: [ adminst ]
  download_state:
    description:
    - The download state of the executable policies.
    - The APIC defaults to C(untriggered) when unset during creation.
    type: str
    choices: [ triggered, untriggered ]
  notify_condition:
    description:
    - Specifies under what pause condition will admin be notified via email/text as configured.
    - This notification mechanism is independent of events/faults.
    - The APIC defaults to C(notifyOnlyOnFailures) when unset during creation.
    type: str
    choices: [ notify_always_between_sets, notify_never, notify_only_on_failures ]
  smu_operation:
    description:
    - Specifies that the upgrade is a Software Maintenance Upgrade (SMU) patch operation.
    type: str
    choices: [ smu_install, smu_uninstall ]
  smu_operation_flags:
    description:
    - Specifies the Software Maintenance Upgrade (SMU) patch operation flags
    - Indicates if node should be reloaded immediately or skip auto reload on SMU Install/Uninstall.
    type: str
    choices: [ smu_reload_immediate, smu_reload_skip ]
  sr_upgrade:
    description:
    - Specifies that the upgrade is a Silent Roll (SR) package upgrade.
    type: bool
    aliases: [ silent_roll_upgrade ]
  sr_version:
    description:
    - The target firmware version of the Silent Roll (SR) package upgrade to install.
    type: str
    aliases: [ silent_roll_version ]
  version:
    description:
    - The target firmware version to install.
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
  ignore_compat:
    description:
    - To check whether compatibility checks should be ignored
    - The APIC defaults to C(false) when unset during creation.
    type: bool
    aliases: [ ignoreCompat ]
  description:
    description:
    - Description for the maintenance policy.
    type: str
    aliases: [ descr ]
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
  name_alias:
    description:
    - The alias for the current object. This relates to the nameAlias field in ACI.
    type: str
extends_documentation_fragment:
- cisco.aci.aci
- cisco.aci.annotation

notes:
- A scheduler is required for this module, which could have been created using the M(cisco.aci.aci_fabric_scheduler) module or via the UI.
seealso:
- module: cisco.aci.aci_fabric_scheduler
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(maint:MaintP).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Steven Gerhart (@sgerhart)
- Gaspard Micol (@gmicol)
"""

EXAMPLES = r"""
- name: Create a maintenance policy
  cisco.aci.aci_maintenance_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: my_maintenance_policy
    scheduler: simpleScheduler
    state: present
  delegate_to: localhost

- name: Delete a maintenance policy
  cisco.aci.aci_maintenance_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: my_maintenance_policy
    state: absent
  delegate_to: localhost

- name: Query all maintenance policies
  cisco.aci.aci_maintenance_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

- name: Query a specific maintenance policy
  cisco.aci.aci_maintenance_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: my_maintenance_policy
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


from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.aci.plugins.module_utils.constants import (
    MATCH_RUN_MODE_MAPPING,
    MATCH_NOTIFY_CONDITION_MAPPING,
    MATCH_SMU_OPERATION_MAPPING,
    MATCH_SMU_OPERATION_FLAGS_MAPPING,
    MATCH_TRIGGER_MAPPING,
)


def main():
    list_run_mode_choices = list(MATCH_RUN_MODE_MAPPING.keys())
    list_run_mode_choices.extend(["pauseOnlyOnFailures", "pauseNever"])
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(
        name=dict(type="str", aliases=["maintenance_policy"]),  # Not required for querying all objects
        run_mode=dict(type="str", choices=list_run_mode_choices, aliases=["runmode"]),
        graceful=dict(type="bool"),
        scheduler=dict(type="str"),
        ignore_compat=dict(type="bool", aliases=["ignoreCompat"]),
        admin_state=dict(type="str", choices=list(MATCH_TRIGGER_MAPPING.keys())[2:], aliases=["adminst"]),
        download_state=dict(type="str", choices=list(MATCH_TRIGGER_MAPPING.keys())[2:]),
        notify_condition=dict(type="str", choices=list(MATCH_NOTIFY_CONDITION_MAPPING.keys())),
        smu_operation=dict(type="str", choices=list(MATCH_SMU_OPERATION_MAPPING.keys())),
        smu_operation_flags=dict(type="str", choices=list(MATCH_SMU_OPERATION_FLAGS_MAPPING.keys())),
        sr_upgrade=dict(type="bool", aliases=["silent_roll_upgrade"]),
        sr_version=dict(type="str", aliases=["silent_roll_version"]),
        version=dict(type="str"),
        version_check_override=dict(type="str", choices=list(MATCH_TRIGGER_MAPPING.keys())),
        description=dict(type="str", aliases=["descr"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        name_alias=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["name"]],
            ["state", "present", ["name", "scheduler"]],
        ],
    )

    aci = ACIModule(module)

    state = module.params.get("state")
    name = module.params.get("name")
    run_mode = module.params.get("run_mode")
    graceful = aci.boolean(module.params.get("graceful"), "yes", "no")
    scheduler = module.params.get("scheduler")
    admin_state = module.params.get("admin_state")
    download_state = module.params.get("download_state")
    notify_condition = MATCH_NOTIFY_CONDITION_MAPPING.get(module.params.get("notify_condition"))
    smu_operation = MATCH_SMU_OPERATION_MAPPING.get(module.params.get("smu_operation"))
    smu_operation_flags = MATCH_SMU_OPERATION_FLAGS_MAPPING.get(module.params.get("smu_operation_flags"))
    sr_version = module.params.get("sr_version")
    sr_upgrade = module.params.get("sr_upgrade")
    version = module.params.get("version")
    version_check_override = MATCH_TRIGGER_MAPPING.get(module.params.get("version_check_override"))
    ignore_compat = aci.boolean(module.params.get("ignore_compat"))
    description = module.params.get("description")
    name_alias = module.params.get("name_alias")

    if run_mode not in ["pauseOnlyOnFailures", "pauseNever"]:
        run_mode = MATCH_RUN_MODE_MAPPING.get(run_mode)

    aci.construct_url(
        root_class=dict(
            aci_class="maintMaintP",
            aci_rn="fabric/maintpol-{0}".format(name),
            target_filter={"name": name},
            module_object=name,
        ),
        child_classes=["maintRsPolScheduler"],
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="maintMaintP",
            class_config=dict(
                name=name,
                descr=description,
                runMode=run_mode,
                graceful=graceful,
                adminSt=admin_state,
                downloadSt=download_state,
                notifCond=notify_condition,
                smuOperation=smu_operation,
                smuOperationFlags=smu_operation_flags,
                srUpgrade=sr_upgrade,
                srVersion=sr_version,
                version=version,
                versionCheckOverride=version_check_override,
                ignoreCompat=ignore_compat,
                nameAlias=name_alias,
            ),
            child_configs=[
                dict(
                    maintRsPolScheduler=dict(
                        attributes=dict(
                            tnTrigSchedPName=scheduler,
                        ),
                    ),
                ),
            ],
        )

        aci.get_diff(aci_class="maintMaintP")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
