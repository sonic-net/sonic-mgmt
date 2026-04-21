#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Anvitha Jain(@anvitha-jain) <anvjain@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_l3out_static_routes
short_description: Manage Static routes object (ip:RouteP)
description:
- Manage External Subnet objects.
options:
  description:
    description:
    - The description for the static routes.
    type: str
    aliases: [ descr ]
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
  logical_node:
    description:
    - Name of an existing logical node profile.
    type: str
    aliases: [ node_profile, node_profile_name ]
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
    - Configure IP and next hop IP for the routed outside network.
    type: str
    aliases: [ route ]
  track_policy:
    description:
    - Relation definition for static route to TrackList.
    type: str
  preference:
    description:
    - Administrative preference value for the route.
    type: int
  bfd:
    description:
    - Determines if bfd is required for route control.
    - The APIC defaults to C(unspecified) when unset during creation.
    type: str
    choices: [ bfd, unspecified ]
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
- The C(tenant), C(l3out), C(logical_node), C(fabric_node) and C(prefix) used must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant) and M(cisco.aci.aci_l3out) modules can be used for this.
seealso:
- module: cisco.aci.aci_tenant
- module: cisco.aci.aci_l3out
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(l3ext:ipRouteP).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Anvitha Jain(@anvitha-jain)
"""

EXAMPLES = r"""
- name: Create static routes
  cisco.aci.aci_l3out_static_routes:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: tenantName
    l3out: l3out
    logical_node: nodeName
    node_id: 101
    pod_id: 1
    prefix: 10.10.0.0/16
  delegate_to: localhost

- name: Delete static routes
  cisco.aci.aci_l3out_static_routes:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: tenantName
    l3out: l3out
    logical_node: nodeName
    node_id: 101
    pod_id: 1
    prefix: 10.10.0.0/16
  delegate_to: localhost

- name: Query for a specific MO under l3out
  cisco.aci.aci_l3out_static_routes:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: tenantName
    l3out: l3out
    logical_node: nodeName
    node_id: 101
    pod_id: 1
    prefix: 10.10.0.0/16
  delegate_to: localhost

- name: Query for all static routes
  cisco.aci.aci_l3out_static_routes:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
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
        tenant=dict(type="str", aliases=["tenant_name"]),  # Not required for querying all objects
        l3out=dict(type="str", aliases=["l3out_name"]),  # Not required for querying all objects
        logical_node=dict(type="str", aliases=["node_profile", "node_profile_name"]),  # Not required for querying all objects
        pod_id=dict(type="int"),
        node_id=dict(type="int"),
        prefix=dict(type="str", aliases=["route"]),
        track_policy=dict(type="str"),
        preference=dict(type="int"),
        bfd=dict(type="str", choices=["bfd", "unspecified"]),
        description=dict(type="str", aliases=["descr"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        name_alias=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "present", ["prefix", "node_id", "pod_id", "logical_node", "l3out", "tenant"]],
            ["state", "absent", ["prefix", "node_id", "pod_id", "logical_node", "l3out", "tenant"]],
        ],
    )

    aci = ACIModule(module)

    tenant = module.params.get("tenant")
    l3out = module.params.get("l3out")
    logical_node = module.params.get("logical_node")
    node_id = module.params.get("node_id")
    pod_id = module.params.get("pod_id")
    prefix = module.params.get("prefix")
    track_policy = module.params.get("track_policy")
    preference = module.params.get("preference")
    bfd = module.params.get("bfd")
    description = module.params.get("description")
    state = module.params.get("state")
    name_alias = module.params.get("name_alias")

    fabric_node = "topology/pod-{0}/node-{1}".format(pod_id, node_id)
    child_classes = ["ipNexthopP"]
    if track_policy is not None:
        child_classes.append("ipRsRouteTrack")

    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter={"name": tenant},
        ),
        subclass_1=dict(
            aci_class="l3extOut",
            aci_rn="out-{0}".format(l3out),
            module_object=l3out,
            target_filter={"name": l3out},
        ),
        subclass_2=dict(
            aci_class="l3extLNodeP",
            aci_rn="lnodep-{0}".format(logical_node),
            module_object=logical_node,
            target_filter={"name": logical_node},
        ),
        subclass_3=dict(
            aci_class="l3extRsNodeL3OutAtt",
            aci_rn="rsnodeL3OutAtt-[{0}]".format(fabric_node),
            module_object=fabric_node,
            target_filter={"name": fabric_node},
        ),
        subclass_4=dict(
            aci_class="ipRouteP",
            aci_rn="rt-[{0}]".format(prefix),
            module_object=prefix,
            target_filter={"name": prefix},
        ),
        child_classes=child_classes,
    )

    aci.get_existing()

    if state == "present":
        child_configs = []
        class_config = dict(
            descr=description,
            ip=prefix,
            pref=preference,
            nameAlias=name_alias,
        )
        if bfd is not None:
            class_config["rtCtrl"] = bfd

        if track_policy is not None:
            tDn = "uni/tn-{0}/tracklist-{1}".format(tenant, track_policy)
            child_configs.append({"ipRsRouteTrack": {"attributes": {"tDn": tDn}}})

        aci.payload(aci_class="ipRouteP", class_config=class_config, child_configs=child_configs)

        aci.get_diff(aci_class="ipRouteP")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
