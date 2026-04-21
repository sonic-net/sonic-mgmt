#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Tim Cragg <tcragg@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_syslog_source
short_description: Manage Syslog Source objects (syslog:Src)
description:
- Manage Syslog Source objects.
options:
  name:
    description:
    - Name of the Syslog Source policy
    type: str
    aliases: [ syslog_src, syslog_source ]
  include:
    description:
    - List of message types to include
    - The APIC defaults to C(faults) when unset during creation.
    type: list
    elements: str
    choices: [ audit, events, faults, session ]
  min_severity:
    description:
    - Minimum Severity of message to include
    type: str
    choices: [ alerts, critical, debugging, emergencies, errors, information, notifications, warnings ]
  destination_group:
    description:
    - Name of an existing syslog group
    type: str
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    default: present
    choices: [ absent, present, query ]
extends_documentation_fragment:
- cisco.aci.aci
- cisco.aci.annotation

seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(syslog:Src).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
"""

EXAMPLES = r"""
- name: Add a new syslog source
  cisco.aci.aci_syslog_source:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: my_syslog_src
    include:
      - audit
      - events
      - faults
    min_severity: errors
    destination_group: my_syslog_group
    state: present
  delegate_to: localhost

- name: Remove an existing syslog source
  cisco.aci.aci_syslog_source:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: my_syslog_src
    state: absent
  delegate_to: localhost

- name: Query all syslog sources
  cisco.aci.aci_syslog_source:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

- name: Query a specific syslog source
  cisco.aci.aci_syslog_source:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: my_syslog_src
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
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(
        name=dict(type="str", aliases=["syslog_src", "syslog_source"]),
        include=dict(type="list", elements="str", choices=["audit", "events", "faults", "session"]),
        min_severity=dict(type="str", choices=["alerts", "critical", "debugging", "emergencies", "errors", "information", "notifications", "warnings"]),
        destination_group=dict(type="str"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["name"]],
            ["state", "present", ["name"]],
        ],
    )

    name = module.params.get("name")
    include = module.params.get("include")
    min_severity = module.params.get("min_severity")
    destination_group = module.params.get("destination_group")
    state = module.params.get("state")

    aci = ACIModule(module)
    aci.construct_url(
        root_class=dict(
            aci_class="syslogSrc",
            aci_rn="fabric/moncommon/slsrc-{0}".format(name),
            module_object=name,
            target_filter={"name": name},
        ),
        child_classes=["syslogRsDestGroup"],
    )

    aci.get_existing()

    if state == "present":
        class_config = dict(name=name, minSev=min_severity)
        if include:
            class_config["incl"] = ",".join(include)

        aci.payload(
            aci_class="syslogSrc",
            class_config=class_config,
            child_configs=[
                dict(
                    syslogRsDestGroup=dict(
                        attributes=dict(tDn=("uni/fabric/slgroup-{0}".format(destination_group))),
                    ),
                ),
            ],
        )

        aci.get_diff(aci_class="syslogSrc")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
