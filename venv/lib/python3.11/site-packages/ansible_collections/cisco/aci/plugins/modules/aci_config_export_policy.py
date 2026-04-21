#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Tim Cragg (@timcragg) <tcragg@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_config_export_policy
short_description: Manage Configuration Export Policy (config:ExportP)
description:
- Manage Configuration Export Policies on Cisco ACI fabrics.
options:
  name:
    description:
    - The name of the Configuration Export Policy.
    type: str
  description:
    description:
    - The description of the Configuration Export Policy.
    type: str
  format:
    description:
    - The format of the export file.
    - This defaults to json on the APIC when unset on creation.
    type: str
    choices: [ json, xml ]
  target_dn:
    description:
    - The distinguished name of the object to be exported.
    - If no target_dn is included, the APIC will export the policy universe.
    type: str
  snapshot:
    description:
    - Enables a snapshot of the configuration export policy.
    - This defaults to False on the APIC when unset on creation.
    type: bool
  export_destination:
    description:
    - The name of the remote path policy used for storing the generated configuration backup data for the configuration export policy.
    type: str
  scheduler:
    description:
    - The name of the scheduler policy used for running scheduled export jobs.
    type: str
  start_now:
    description:
    - Specifies if the configuration export policy should be applied now or at another time.
    - This defaults to False on the APIC when unset on creation.
    type: bool
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
extends_documentation_fragment:
- cisco.aci.aci
- cisco.aci.annotation

seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(config:ExportP).
  link: https://developer.cisco.com/docs/apic-mim-ref/

author:
- Tim Cragg (@timcragg)
"""

EXAMPLES = r"""
- name: Add a Configuration Export Policy
  cisco.aci.aci_config_export_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: ans_conf_export
    state: present
  delegate_to: localhost

- name: Query a Configuration Export Policy
  cisco.aci.aci_config_export_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: ans_conf_export
    state: query
  delegate_to: localhost

- name: Query all Configuration Export Policies
  cisco.aci.aci_config_export_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost

- name: Remove a Configuration Export Policies
  cisco.aci.aci_file_remote_path:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: ans_conf_export
    state: absent
  delegate_to: localhost
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
        name=dict(type="str"),
        description=dict(type="str"),
        format=dict(type="str", choices=["json", "xml"]),
        target_dn=dict(type="str"),
        snapshot=dict(type="bool"),
        export_destination=dict(type="str"),
        scheduler=dict(type="str"),
        start_now=dict(type="bool"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "present", ["name"]],
            ["state", "absent", ["name"]],
        ],
    )

    aci = ACIModule(module)

    name = module.params.get("name")
    description = module.params.get("description")
    format = module.params.get("format")
    target_dn = module.params.get("target_dn")
    snapshot = aci.boolean(module.params.get("snapshot"))
    export_destination = module.params.get("export_destination")
    scheduler = module.params.get("scheduler")
    start_now = aci.boolean(module.params.get("start_now"), "triggered", "untriggered")
    state = module.params.get("state")

    aci.construct_url(
        root_class=dict(
            aci_class="configExportP",
            aci_rn="fabric/configexp-{0}".format(name),
            module_object=name,
            target_filter={"name": name},
        ),
        child_classes=["configRsExportScheduler", "configRsRemotePath"],
    )
    aci.get_existing()

    if state == "present":
        child_configs = []
        if scheduler is not None:
            child_configs.append(
                dict(
                    configRsExportScheduler=dict(
                        attributes=dict(tnTrigSchedPName=scheduler),
                    )
                )
            )
        if export_destination is not None:
            child_configs.append(
                dict(
                    configRsRemotePath=dict(
                        attributes=dict(tnFileRemotePathName=export_destination),
                    )
                )
            )
        aci.payload(
            aci_class="configExportP",
            class_config=dict(
                name=name,
                descr=description,
                format=format,
                targetDn=target_dn,
                snapshot=snapshot,
                adminSt=start_now,
            ),
            child_configs=child_configs,
        )

        aci.get_diff(aci_class="configExportP")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
