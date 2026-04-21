#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Tim Cragg (@timcragg) <tcragg@cisco.com>
# Copyright: (c) 2023, Akini Ross (@akinross) <akinross@cisco.com
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_fabric_node_control
short_description: Manage Fabric Node Controls (fabric:NodeControl)
description:
- Manage Fabric Node Controls on ACI fabrics.
options:
  name:
    description:
    - The name of the Fabric Node Control.
    type: str
    aliases: [ fabric_node_control ]
  description:
    description:
    - The description of the Fabric Node Control.
    type: str
  enable_dom:
    description:
    - Whether to enable digital optical monitoring (DOM) for the fabric node control.
    - The APIC defaults to C(false) when unset during creation.
    type: bool
  feature_selection:
    description:
    - The feature selection for the Node Control.
    - The APIC defaults to C(telemetry) when unset during creation.
    type: str
    choices: [ analytics, netflow, telemetry ]
    aliases: [ feature ]
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
- cisco.aci.owner

seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(fabric:NodeControl).
  link: https://developer.cisco.com/docs/apic-mim-ref/

author:
- Tim Cragg (@timcragg)
- Akini Ross (@akinross)
"""

EXAMPLES = r"""
- name: Create Fabric Node Control
  cisco.aci.aci_fabric_node_control:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: ans_fab_node_control
    enable_dom: true
    feature_selection: netflow
    state: present
  delegate_to: localhost

- name: Delete Fabric Node Control
  cisco.aci.aci_fabric_node_control:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: ans_fab_node_control
    state: absent
  delegate_to: localhost

- name: Query Fabric Node Control
  cisco.aci.aci_fabric_node_control:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: ans_fab_node_control
    state: query
  delegate_to: localhost

- name: Query All Fabric Node Controls
  cisco.aci.aci_fabric_node_control:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
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
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec, aci_owner_spec


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        name=dict(type="str", aliases=["fabric_node_control"]),
        description=dict(type="str"),
        enable_dom=dict(type="bool"),
        feature_selection=dict(type="str", choices=["analytics", "netflow", "telemetry"], aliases=["feature"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )
    aci = ACIModule(module)

    name = module.params.get("name")
    description = module.params.get("description")
    enable_dom = aci.boolean(module.params.get("enable_dom"), "Dom", "None")
    feature_selection = module.params.get("feature_selection")
    state = module.params.get("state")

    aci.construct_url(
        root_class=dict(
            aci_class="fabricNodeControl",
            aci_rn="fabric/nodecontrol-{0}".format(name),
            module_object=name,
            target_filter={"name": name},
        ),
    )
    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="fabricNodeControl",
            class_config=dict(
                name=name,
                descr=description,
                control=enable_dom,
                featureSel=feature_selection,
            ),
        )

        aci.get_diff(aci_class="fabricNodeControl")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
