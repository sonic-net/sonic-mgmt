#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Akini Ross <akinross@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_fabric_span_src_group_src_path
short_description: Manage Fabric SPAN source paths (span:RsSrcToPathEp)
description:
- Manage Fabric SPAN source paths on Cisco ACI fabrics.
options:
  source_group:
    description:
    - The name of the Fabric SPAN source group.
    type: str
    aliases: [ src_group ]
  source:
    description:
    - The name of the Fabric SPAN source.
    type: str
    aliases: [ src ]
  pod:
    description:
    - The pod id of the source access path.
    type: int
    aliases: [ pod_id, pod_number ]
  node:
    description:
    - The node id of the source access path.
    type: int
    aliases: [ node_id ]
  path_ep:
    description:
    - The path of the source access path.
    - An interface like C(eth1/7) must be provided.
    type: str
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

notes:
- The I(source_group), and I(source) must exist before using this module in your playbook.
  The M(cisco.aci.aci_fabric_span_src_group) and M(cisco.aci.aci_fabric_span_src_group_src) modules can be used for this.
seealso:
- module: cisco.aci.aci_fabric_span_src_group
- module: cisco.aci.aci_fabric_span_src_group_src
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(span:RsSrcToPathEp).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Akini Ross (@akinross)
"""

EXAMPLES = r"""
- name: Create a Fabric SPAN source path of type path
  cisco.aci.aci_fabric_span_src_group_src_path:
    host: apic
    username: admin
    password: SomeSecretPassword
    source_group: my_span_source_group
    source: my_source
    pod: 1
    node: 101
    path_ep: eth1/1
    state: present
  delegate_to: localhost

- name: Delete a Fabric SPAN source path
  cisco.aci.aci_fabric_span_src_group_src_path:
    host: apic
    username: admin
    password: SomeSecretPassword
    source_group: my_span_source_group
    source: my_source
    pod: 1
    node: 101
    path_ep: eth1/1
    state: absent
  delegate_to: localhost

- name: Query all Fabric SPAN source paths
  cisco.aci.aci_fabric_span_src_group_src_path:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

- name: Query a specific Fabric SPAN source path
  cisco.aci.aci_fabric_span_src_group_src_path:
    host: apic
    username: admin
    password: SomeSecretPassword
    source_group: my_span_source_group
    source: my_source
    pod: 1
    node: 101
    path_ep: eth1/1
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
        source_group=dict(type="str", aliases=["src_group"]),  # Not required for querying all objects
        source=dict(type="str", aliases=["src"]),  # Not required for querying all objects
        pod=dict(type="int", aliases=["pod_id", "pod_number"]),  # Not required for querying all objects
        node=dict(type="int", aliases=["node_id"]),  # Not required for querying all objects
        path_ep=dict(type="str"),  # Not required for querying all objects
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["source_group", "source", "pod", "node", "path_ep"]],
            ["state", "present", ["source_group", "source", "pod", "node", "path_ep"]],
        ],
    )

    aci = ACIModule(module)

    source_group = module.params.get("source_group")
    source = module.params.get("source")
    pod = module.params.get("pod")
    node = module.params.get("node")
    path_ep = module.params.get("path_ep")
    state = module.params.get("state")

    tdn = None
    if pod and node and path_ep:
        tdn = "topology/pod-{0}/paths-{1}/pathep-[{2}]".format(pod, node, path_ep)

    aci.construct_url(
        root_class=dict(
            aci_class="fabric",
            aci_rn="fabric",
        ),
        subclass_1=dict(
            aci_class="spanSrcGrp",
            aci_rn="srcgrp-{0}".format(source_group),
            module_object=source_group,
            target_filter={"name": source_group},
        ),
        subclass_2=dict(
            aci_class="spanSrc",
            aci_rn="src-{0}".format(source),
            module_object=source,
            target_filter={"name": source},
        ),
        subclass_3=dict(
            aci_class="spanRsSrcToPathEp",
            aci_rn="rssrcToPathEp-[{0}]".format(tdn),
            module_object=tdn,
            target_filter={"tDn": tdn},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(aci_class="spanRsSrcToPathEp", class_config=dict(tDn=tdn))

        aci.get_diff(aci_class="spanRsSrcToPathEp")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
