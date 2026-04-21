#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Tim Cragg (@timcragg)
# Copyright: (c) 2025, Shreyas Srish (@shrsr)
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: aci_l4l7_policy_based_redirect_destination
version_added: "2.12.0"
short_description: Manage L4-L7 Policy Based Redirect Destinations (vns:RedirectDest and vns:L1L2RedirectDest)
description:
- Manage L4-L7 Policy Based Redirect Destinations
options:
  tenant:
    description:
    - The name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
  policy:
    description:
    - The name of an existing Policy Based Redirect Policy.
    type: str
    aliases: [ policy_name ]
  description:
    description:
    - The description for redirection.
    type: str
  ip:
    description:
    - The destination IP for redirection.
    - Only used if I(destination_type=l3)
    aliases: [ redirect_ip ]
    type: str
  additional_ip:
    description:
    - The Additional IP Address for the Destination.
    - Only used if I(destination_type=l3)
    type: str
  logical_device:
    description:
    - The destination Logical Device for redirection.
    - Only used if I(destination_type=l1/l2)
    type: str
    aliases: [ logical_dev ]
  concrete_device:
    description:
    - The destination Concrete Device for redirection.
    - Only used if I(destination_type=l1/l2)
    type: str
    aliases: [ concrete_dev ]
  concrete_interface:
    description:
    - The destination Concrete Interface for redirection.
    - Only used if I(destination_type=l1/l2)
    type: str
    aliases: [ concrete_intf ]
  mac:
    description:
    - The destination MAC address for redirection.
    type: str
    aliases: [ redirect_mac ]
  destination_name:
    description:
    - The name for Policy Based Redirect destination.
    type: str
    aliases: [ dest_name ]
  destination_type:
    description:
    - The destination type.
    type: str
    choices: [ l1/l2, l3 ]
    aliases: [ dest_type ]
    default: l3
  pod_id:
    description:
    - The Pod ID to deploy Policy Based Redirect destination on.
    - The APIC defaults to 1 when unset during creation.
    type: int
  health_group:
    description:
    - The Health Group to bind the Policy Based Redirection Destination to.
    - To remove an existing binding from a Health Group, submit a request with I(state=present) and I(health_group="") value.
    type: str
  weight:
    description:
    - The weight of the fault in calculating the health score of an object.
    - The APIC defaults to 1 when unset during creation.
    - Permitted values are in the range of [1, 10].
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
notes:
- The I(tenant), I(device), I(concrete_device), I(concrete_interface) and I(policy) must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant), M(cisco.aci.aci_l4l7_device), M(cisco.aci.aci_l4l7_concrete_device), M(cisco.aci.aci_l4l7_concrete_interface)
  and M(cisco.aci.aci_l4l7_policy_based_redirect) modules can be used for this.
seealso:
- module: cisco.aci.aci_tenant
- module: cisco.aci.aci_l4l7_device
- module: cisco.aci.aci_l4l7_concrete_device
- module: cisco.aci.aci_l4l7_concrete_interface
- module: cisco.aci.aci_l4l7_policy_based_redirect
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(vns:RedirectDest), B(vns:L1L2RedirectDest)
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
- Shreyas Srish (@shrsr)
"""

EXAMPLES = r"""
- name: Add destination to a Policy Based Redirect Policy
  cisco.aci.aci_l4l7_policy_based_redirect_destination:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    policy: my_pbr_policy
    destination_type: l3
    ip: 192.168.10.1
    mac: AB:CD:EF:12:34:56
    destination_name: redirect_dest
    pod_id: 1
    state: present
  delegate_to: localhost

- name: Query destinations for a Policy Based Redirect Policy
  cisco.aci.aci_l4l7_policy_based_redirect_destination:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    policy: my_pbr_policy
    state: query
  delegate_to: localhost
  register: query_result

- name: Query destinations for all Policy Based Redirect Policies
  cisco.aci.aci_l4l7_policy_based_redirect_destination:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

- name: Remove destination from a Policy Based Redirect Policy
  cisco.aci.aci_l4l7_policy_based_redirect_destination:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    policy: my_pbr_policy
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
        tenant=dict(type="str", aliases=["tenant_name"]),
        policy=dict(type="str", aliases=["policy_name"]),
        ip=dict(type="str", aliases=["redirect_ip"]),
        additional_ip=dict(type="str"),
        mac=dict(type="str", aliases=["redirect_mac"]),
        logical_device=dict(type="str", aliases=["logical_dev"]),
        concrete_device=dict(type="str", aliases=["concrete_dev"]),
        concrete_interface=dict(type="str", aliases=["concrete_intf"]),
        destination_name=dict(type="str", aliases=["dest_name"]),
        destination_type=dict(type="str", aliases=["dest_type"], choices=["l1/l2", "l3"], default="l3"),
        health_group=dict(type="str"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        pod_id=dict(type="int"),
        weight=dict(type="int"),
        description=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["tenant", "policy"]],
            ["state", "present", ["tenant", "policy"]],
        ],
    )

    aci = ACIModule(module)

    tenant = module.params.get("tenant")
    state = module.params.get("state")
    policy = module.params.get("policy")
    ip = module.params.get("ip")
    additional_ip = module.params.get("additional_ip")
    mac = module.params.get("mac")
    logical_device = module.params.get("logical_device")
    concrete_device = module.params.get("concrete_device")
    concrete_interface = module.params.get("concrete_interface")
    destination_name = module.params.get("destination_name")
    destination_type = module.params.get("destination_type")
    health_group = module.params.get("health_group")
    state = module.params.get("state")
    pod_id = module.params.get("pod_id")
    weight = module.params.get("weight")
    description = module.params.get("description")

    if destination_type == "l1/l2":
        aci_class = "vnsL1L2RedirectDest"
        aci_rn = "L1L2RedirectDest-[{0}]".format(destination_name)
        module_object = destination_name
        target_filter = {"destName": destination_name}
        child_classes = ["vnsRsL1L2RedirectHealthGroup", "vnsRsToCIf"]
        redirect_hg_class = "vnsRsL1L2RedirectHealthGroup"
    else:
        aci_class = "vnsRedirectDest"
        aci_rn = "RedirectDest_ip-[{0}]".format(ip)
        module_object = ip
        target_filter = {"ip": ip}
        child_classes = ["vnsRsRedirectHealthGroup"]
        redirect_hg_class = "vnsRsRedirectHealthGroup"

    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter={"name": tenant},
        ),
        subclass_1=dict(
            aci_class="vnsSvcRedirectPol",
            aci_rn="svcCont/svcRedirectPol-{0}".format(policy),
            module_object=policy,
            target_filter={"name": policy},
        ),
        subclass_2=dict(
            aci_class=aci_class,
            aci_rn=aci_rn,
            module_object=module_object,
            target_filter=target_filter,
        ),
        child_classes=child_classes,
    )
    aci.get_existing()

    if state == "present":
        if destination_type == "l1/l2" and additional_ip is not None:
            aci.fail_json(msg="You cannot provide an additional_ip when configuring an l1/l2 destination")
        elif destination_type == "l3" and (logical_device, concrete_device, concrete_interface) != (None, None, None):
            aci.fail_json(msg="You cannot provide a logical_device, concrete_device or concrete_interface when configuring an l3 destination")
        elif destination_type == "l1/l2" and (logical_device, concrete_device, concrete_interface) == (None, None, None):
            aci.fail_json(msg="You must provide a logical_device, concrete_device and concrete_interface when configuring an l1/l2 destination")
        elif destination_type == "l1/l2" and ip is not None:
            aci.fail_json(msg="You cannot provide an ip when configuring an l1/l2 destination")
        child_configs = []
        if destination_type == "l1/l2":
            child_configs = [
                {
                    "vnsRsToCIf": {
                        "attributes": {"tDn": "uni/tn-{0}/lDevVip-{1}/cDev-{2}/cIf-[{3}]".format(tenant, logical_device, concrete_device, concrete_interface)}
                    }
                }
            ]
        if health_group:
            health_group_tdn = "uni/tn-{0}/svcCont/redirectHealthGroup-{1}".format(tenant, health_group)
            child_configs.append({redirect_hg_class: {"attributes": {"tDn": health_group_tdn}}})
        else:
            health_group_tdn = None
        if isinstance(aci.existing, list) and len(aci.existing) > 0:
            for child in aci.existing[0].get(aci_class, {}).get("children", {}):
                if child.get(redirect_hg_class) and child.get(redirect_hg_class).get("attributes").get("tDn") != health_group_tdn:
                    child_configs.append(
                        {
                            redirect_hg_class: {
                                "attributes": {
                                    "dn": child.get(redirect_hg_class).get("attributes").get("dn"),
                                    "status": "deleted",
                                }
                            }
                        }
                    )
        aci.payload(
            aci_class=aci_class,
            class_config=dict(
                ip=ip,
                mac=mac,
                destName=destination_name,
                podId=pod_id,
                ip2=additional_ip,
                weight=weight,
                descr=description,
            ),
            child_configs=child_configs,
        )
        aci.get_diff(aci_class=aci_class)

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
