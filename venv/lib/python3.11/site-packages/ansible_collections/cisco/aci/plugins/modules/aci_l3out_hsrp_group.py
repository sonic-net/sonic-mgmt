#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: aci_l3out_hsrp_group
short_description: Manage HSRP group (hsrp:GroupP) of the HSRP interface profile (hsrp:IfP)
description:
- Manage HSRP group of the HSRP interface profile on Cisco ACI fabrics.
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
  interface_profile:
    description:
    - Name of an existing interface profile.
    type: str
    aliases: [ interface_profile_name, logical_interface ]
  hsrp_interface_group:
    description:
    - Name of the HSRP interface group.
    type: str
    aliases: [ name, hsrp_group ]
  group_id:
    description:
    - The group id of the HSRP interface group.
    type: int
  ip:
    description:
    - The virtual IP address of the HSRP interface group.
    type: str
  mac:
    description:
    - The MAC address of the HSRP interface group.
    type: str
  group_name:
    description:
    - The group name is used to define and manage the specific HSRP interface group, facilitating high availability in the network.
    type: str
  description:
    description:
    - The description of the HSRP interface group.
    type: str
    aliases: [ descr ]
  group_type:
    description:
    - The type of the HSRP interface group.
    type: str
    choices: [ ipv4, ipv6 ]
  ip_obtain_mode:
    description:
    - The mode of method used to obtain the IP address.
    type: str
    choices: [ admin, auto, learn ]
  group_policy:
    description:
    - The group policy of the HSRP interface group.
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
- cisco.aci.owner

notes:
- The C(tenant), C(l3out), C(logical_node_profile), C(logical_interface_profile) and C(hsrp_interface_profile) must exist before using this module in
  your playbook. The M(cisco.aci.aci_tenant), M(cisco.aci.aci_l3out), M(cisco.aci.aci_l3out_logical_node_profile),
  M(cisco.aci.aci_l3out_logical_interface_profile) and M(cisco.aci.aci_l3out_hsrp_interface_profile) can be used for this.
seealso:
- module: cisco.aci.aci_tenant
- module: cisco.aci.aci_l3out
- module: cisco.aci.aci_l3out_logical_node_profile
- module: cisco.aci.aci_l3out_logical_interface_profile
- module: cisco.aci.aci_l3out_hsrp_interface_profile
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(hsrp:IfP).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Shreyas Srish (@shrsr)
"""

EXAMPLES = r"""
- name: Add a new HSRP group
  cisco.aci.aci_l3out_hsrp_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    l3out: my_l3out
    node_profile: my_node_profile
    interface_profile: my_interface_profile
    hsrp_interface_group: group1
    ip: 12.34.56.32
    group_type: ipv4
    ip_obtain_mode: admin
    group_policy: default
    state: present
  delegate_to: localhost

- name: Delete a HSRP group
  cisco.aci.aci_l3out_hsrp_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    l3out: my_l3out
    node_profile: my_node_profile
    interface_profile: my_interface_profile
    hsrp_interface_group: group1
    ip: 12.34.56.32
    group_type: ipv4
    ip_obtain_mode: admin
    group_policy: default
    state: absent
  delegate_to: localhost

- name: Query a HSRP group
  cisco.aci.aci_l3out_hsrp_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    l3out: my_l3out
    node_profile: my_node_profile
    interface_profile: my_interface_profile
    hsrp_interface_group: group1
    ip: 12.34.56.32
    group_type: ipv4
    ip_obtain_mode: admin
    group_policy: default
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all HSRP groups
  cisco.aci.aci_l3out_hsrp_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    l3out: my_l3out
    node_profile: my_node_profile
    interface_profile: my_interface_profile
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
        tenant=dict(type="str", aliases=["tenant_name"]),
        l3out=dict(type="str", aliases=["l3out_name"]),
        node_profile=dict(type="str", aliases=["node_profile_name", "logical_node"]),
        interface_profile=dict(type="str", aliases=["interface_profile_name", "logical_interface"]),
        hsrp_interface_group=dict(type="str", aliases=["name", "hsrp_group"]),
        group_id=dict(type="int"),
        ip=dict(type="str"),
        mac=dict(type="str"),
        group_name=dict(type="str"),
        description=dict(type="str", aliases=["descr"]),
        group_type=dict(type="str", choices=["ipv4", "ipv6"]),
        ip_obtain_mode=dict(type="str", choices=["admin", "auto", "learn"]),
        group_policy=dict(type="str"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["tenant", "l3out", "node_profile", "interface_profile", "hsrp_interface_group"]],
            ["state", "present", ["tenant", "l3out", "node_profile", "interface_profile", "hsrp_interface_group"]],
        ],
    )

    tenant = module.params.get("tenant")
    l3out = module.params.get("l3out")
    node_profile = module.params.get("node_profile")
    interface_profile = module.params.get("interface_profile")
    hsrp_interface_group = module.params.get("hsrp_interface_group")
    group_id = module.params.get("group_id")
    ip = module.params.get("ip")
    mac = module.params.get("mac")
    group_name = module.params.get("group_name")
    description = module.params.get("description")
    group_type = module.params.get("group_type")
    ip_obtain_mode = module.params.get("ip_obtain_mode")
    group_policy = module.params.get("group_policy")
    state = module.params.get("state")

    aci = ACIModule(module)

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
            aci_rn="lnodep-{0}".format(node_profile),
            module_object=node_profile,
            target_filter={"name": node_profile},
        ),
        subclass_3=dict(
            aci_class="l3extLIfP",
            aci_rn="lifp-[{0}]".format(interface_profile),
            module_object=interface_profile,
            target_filter={"name": interface_profile},
        ),
        subclass_4=dict(
            aci_class="hsrpIfP",
            aci_rn="hsrpIfP",
            module_object=interface_profile,
            target_filter={"name": interface_profile},
        ),
        subclass_5=dict(
            aci_class="hsrpGroupP",
            aci_rn="hsrpGroupP-{0}".format(hsrp_interface_group),
            module_object=hsrp_interface_group,
            target_filter={"name": hsrp_interface_group},
        ),
        child_classes=["hsrpRsGroupPol"],
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="hsrpGroupP",
            class_config=dict(groupAf=group_type, groupId=group_id, groupName=group_name, ip=ip, ipObtainMode=ip_obtain_mode, mac=mac, descr=description),
            child_configs=[dict(hsrpRsGroupPol=dict(attributes=dict(tnHsrpGroupPolName=group_policy)))] if group_policy is not None else [],
        )

        aci.get_diff(aci_class="hsrpGroupP")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
