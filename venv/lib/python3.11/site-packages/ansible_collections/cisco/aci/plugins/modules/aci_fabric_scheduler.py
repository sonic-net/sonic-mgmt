#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: aci_fabric_scheduler
short_description: This module creates ACI schedulers (trig:SchedP)
description:
- With the module you can create schedule policies that can be a shell, one-time execution or recurring.
options:
  name:
    description:
    - The name of the Scheduler.
    type: str
    aliases: [ scheduler_name ]
  description:
    description:
    - Description for the Scheduler.
    type: str
    aliases: [ descr ]
  recurring:
    description:
    - If you want to make the scheduler a recurring operation, it should be set C(True) and for a one-time execution it should be C(False).
    - For a shell, just exclude this option from the task.
    type: bool
  windowname:
    description:
    - The name of the schedule window.
    - This is mandatory for the child class object B(trig:AbsWinddowP)
    type: str
  concurCap:
    description:
    - The amount of devices that can be executed on at a time.
    type: int
  maxTime:
    description:
    - The maximum amount of time a process can be executed.
    type: str
  date:
    description:
    - The date and time that the scheduler will execute.
    type: str
  hour:
    description:
    - The number of hours of execution.
    type: int
  minute:
    description:
    - The number of minutes of execution, used in conjunction with hour.
    type: int
  day:
    description:
    - The number of days when execution will take place.
    type: str
    default: every-day
    choices: [ Monday, Tuesday, Wednesday, Thursday, Friday, Saturday, Sunday, even-day, odd-day, every-day ]
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    default: present
    choices: [ absent, present, query ]
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
  description: More information about the internal APIC class B(trig:SchedP).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Steven Gerhart (@sgerhart)
"""

EXAMPLES = r"""
- name: Simple Scheduler (Empty)
  cisco.aci.aci_fabric_scheduler:
    host: "{{ inventory_hostname }}"
    username: "{{ user }}"
    password: "{{ pass }}"
    validate_certs: false
    name: simpleScheduler
    state: present

- name: Remove Simple Scheduler
  cisco.aci.aci_fabric_scheduler:
    host: "{{ inventory_hostname }}"
    username: "{{ user }}"
    password: "{{ pass }}"
    validate_certs: false
    name: simpleScheduler
    state: absent

- name: One Time Scheduler
  cisco.aci.aci_fabric_scheduler:
    host: "{{ inventory_hostname }}"
    username: "{{ user }}"
    password: "{{ pass }}"
    validate_certs: false
    name: OneTime
    windowname: OneTime
    recurring: false
    concurCap: 20
    date: "2018-11-20T24:00:00"
    state: present

- name: Recurring Scheduler
  cisco.aci.aci_fabric_scheduler:
    host: "{{ inventory_hostname }}"
    username: "{{ user }}"
    password: "{{ pass }}"
    validate_certs: false
    name: Recurring
    windowname: Recurring
    recurring: true
    concurCap: 20
    hour: 13
    minute: 30
    day: Tuesday
    state: present
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


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        name=dict(type="str", aliases=["scheduler_name"]),  # Not required for querying all objects
        description=dict(type="str", aliases=["descr"]),
        windowname=dict(type="str"),
        recurring=dict(type="bool"),
        concurCap=dict(type="int"),  # Number of devices it will run against concurrently
        maxTime=dict(type="str"),  # The amount of minutes a process will be able to run (unlimited or dd:hh:mm:ss)
        date=dict(type="str"),  # The date the process will run YYYY-MM-DDTHH:MM:SS
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        hour=dict(type="int"),
        minute=dict(type="int"),
        day=dict(
            type="str",
            default="every-day",
            choices=["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday", "every-day", "even-day", "odd-day"],
        ),
        name_alias=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["name"]],
            ["state", "present", ["name"]],
        ],
    )

    state = module.params.get("state")
    name = module.params.get("name")
    windowname = module.params.get("windowname")
    recurring = module.params.get("recurring")
    date = module.params.get("date")
    hour = module.params.get("hour")
    minute = module.params.get("minute")
    maxTime = module.params.get("maxTime")
    concurCap = module.params.get("concurCap")
    day = module.params.get("day")
    description = module.params.get("description")
    name_alias = module.params.get("name_alias")

    child_classes = [
        "trigRecurrWindowP",
        "trigAbsWindowP",
    ]

    if recurring:
        child_configs = [
            dict(
                trigRecurrWindowP=dict(
                    attributes=dict(
                        name=windowname,
                        hour=hour,
                        minute=minute,
                        procCa=maxTime,
                        concurCap=concurCap,
                        day=day,
                    )
                )
            )
        ]
    elif recurring is False:
        child_configs = [
            dict(
                trigAbsWindowP=dict(
                    attributes=dict(
                        name=windowname,
                        procCap=maxTime,
                        concurCap=concurCap,
                        date=date,
                    )
                )
            )
        ]
    else:
        child_configs = []

    aci = ACIModule(module)
    aci.construct_url(
        root_class=dict(
            aci_class="trigSchedP",
            aci_rn="fabric/schedp-{0}".format(name),
            target_filter={"name": name},
            module_object=name,
        ),
        child_classes=child_classes,
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="trigSchedP",
            class_config=dict(
                name=name,
                descr=description,
                nameAlias=name_alias,
            ),
            child_configs=child_configs,
        )

        aci.get_diff(aci_class="trigSchedP")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
