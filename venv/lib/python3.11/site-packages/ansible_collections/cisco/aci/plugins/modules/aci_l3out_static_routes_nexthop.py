#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: aci_l3out_static_routes_nexthop
short_description: Manage nexthops for static routes (ip:NexthopP)
description:
- Manage nexthops for static routes.
options:
  tenant:
    description:
    - Name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
  l3out:
    description:
    - Name of an existing L3Out.
    type: str
    aliases: [ l3out_name ]
  node_profile:
    description:
    - Name of the node profile.
    type: str
    aliases: [ node_profile_name, logical_node ]
  pod_id:
    description:
    - Existing podId.
    type: int
  node_id:
    description:
    - Existing nodeId.
    type: int
  prefix:
    description:
    - The IP prefix
    type: str
    aliases: [ route ]
  nexthop:
    description:
    - The nexthop for the prefix
    type: str
  preference:
    description:
    - The administrative preference value for the nexthop.
    - The APIC defaults to 0 when unset during creation.
    - The value must be between 0 and 255.
    type: int
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
- module: cisco.aci.aci_l3out
- module: cisco.aci.aci_l3out_logical_node_profile
- module: cisco.aci.aci_l3out_logical_node_profile_to_node
- module: cisco.aci.aci_l3out_static_routes
- name: APIC Management Information Model reference
  description: More information about the internal APIC classes B(ip:NexthopP)
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Marcel Zehnder (@maercu)
"""

EXAMPLES = r"""
- name: Add a new nexthop to a prefix
  cisco.aci.aci_l3out_static_routes_nexthop:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    l3out: my_l3out
    node_profile: my_node_profile
    pod_id: 1
    node_id: 111
    prefix: 10.84.90.0/24
    nexthop: 10.1.1.1
    preference: 1
    state: present
  delegate_to: localhost

- name: Delete a nexthop from a prefix
  cisco.aci.aci_l3out_static_routes_nexthop:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    l3out: my_l3out
    node_profile: my_node_profile
    pod_id: 1
    node_id: 111
    prefix: 10.84.90.0/24
    nexthop: 10.1.1.1
    state: absent
  delegate_to: localhost

- name: Query a nexthop
  cisco.aci.aci_l3out_static_routes_nexthop:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    l3out: my_l3out
    node_profile: my_node_profile
    pod_id: 1
    node_id: 111
    prefix: 10.84.90.0/24
    nexthop: 10.1.1.1
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all nexthops
  cisco.aci.aci_l3out_static_routes_nexthop:
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


from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec
from ansible.module_utils.basic import AnsibleModule


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(
        tenant=dict(type="str", aliases=["tenant_name"]),
        l3out=dict(type="str", aliases=["l3out_name"]),
        node_profile=dict(type="str", aliases=["node_profile_name", "logical_node"]),
        pod_id=dict(type="int"),
        node_id=dict(type="int"),
        prefix=dict(type="str", aliases=["route"]),
        nexthop=dict(type="str"),
        preference=dict(type="int"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["tenant", "l3out", "node_profile", "pod_id", "node_id", "prefix", "nexthop"]],
            ["state", "present", ["tenant", "l3out", "node_profile", "pod_id", "node_id", "prefix", "nexthop"]],
        ],
    )

    tenant = module.params.get("tenant")
    l3out = module.params.get("l3out")
    node_profile = module.params.get("node_profile")
    pod_id = module.params.get("pod_id")
    node_id = module.params.get("node_id")
    prefix = module.params.get("prefix")
    nexthop = module.params.get("nexthop")
    preference = module.params.get("preference")
    state = module.params.get("state")

    node_tdn = None
    if pod_id is not None and node_id is not None:
        node_tdn = "topology/pod-{0}/node-{1}".format(pod_id, node_id)

    aci = ACIModule(module)

    aci.construct_url(
        root_class=dict(aci_class="fvTenant", aci_rn="tn-{0}".format(tenant), module_object=tenant, target_filter={"name": tenant}),
        subclass_1=dict(aci_class="l3extOut", aci_rn="out-{0}".format(l3out), module_object=l3out, target_filter={"name": l3out}),
        subclass_2=dict(aci_class="l3extLNodeP", aci_rn="lnodep-{0}".format(node_profile), module_object=node_profile, target_filter={"name": node_profile}),
        subclass_3=dict(
            aci_class="l3extRsNodeL3OutAtt", aci_rn="rsnodeL3OutAtt-[{0}]".format(node_tdn), module_object=node_tdn, target_filter={"name": node_tdn}
        ),
        subclass_4=dict(aci_class="ipRouteP", aci_rn="rt-[{0}]".format(prefix), module_object=prefix, target_filter={"name": prefix}),
        subclass_5=dict(aci_class="ipNexthopP", aci_rn="nh-[{0}]".format(nexthop), module_object=nexthop, target_filter={"name": nexthop}),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(aci_class="ipNexthopP", class_config=dict(nhAddr=nexthop, pref=preference))

        aci.get_diff(aci_class="ipNexthopP")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
