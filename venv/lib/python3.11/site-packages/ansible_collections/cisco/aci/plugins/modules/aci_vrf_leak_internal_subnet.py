#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Abraham Mughal (@abmughal) abmughal@cisco.com
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_vrf_leak_internal_subnet
short_description: Manage VRF leaking of subnets (leak:InternalSubnet)
description:
- Manage the leaking of internal subnets under the VRF.
options:
  tenant:
    description:
    - The name of the Tenant the VRF belongs to.
    type: str
    aliases: [ tenant_name ]
  vrf:
    description:
    - The name of the VRF.
    type: str
    aliases: [ context, name, vrf_name ]
  description:
    description:
    - The description for the VRF Leak Internal Subnet.
    type: str
    aliases: [ descr ]
  name_alias:
    description:
    - The alias for the current object. This relates to the nameAlias field in ACI.
    type: str
  scope:
    description:
    - Scope of the object.
    type: str
    choices: [ public, private, shared ]
    default: private
  leak_to:
    description:
    - The VRFs to leak the subnet routes into.
    type: list
    elements: dict
    suboptions:
      tenant:
        description:
        - Name of the tenant.
        type: str
        aliases: [ tenant_name ]
      vrf:
        description:
        - Name of the VRF.
        type: str
        aliases: [ vrf_name ]
  ip:
    description:
    - The IP address / subnet used to match routes to be leaked.
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
- The C(tenant) and C(vrf) used must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant) and M(cisco.aci.aci_vrf) modules can be used for this.
seealso:
- module: cisco.aci.aci_tenant
- module: cisco.aci.aci_vrf
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(leak:InternalSubnet).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Abraham Mughal (@abmughal)
"""

EXAMPLES = r"""
- name: Create leak internal subnet
  cisco.aci.aci_vrf_leak_internal_subnet:
    host: apic
    username: admin
    password: SomeSecretPassword
    vrf: vrf_lab
    tenant: lab_tenant
    descr: Lab VRF
    state: present
    leak_to:
      - vrf: "test"
        tenant: "lab_tenant"
      - vrf: "test2"
        tenant: "lab_tenant"
    description: Ansible Test
    ip: 1.1.1.2
  delegate_to: localhost

- name: Remove a subnet from leaking
  cisco.aci.aci_vrf_leak_internal_subnet:
    host: apic
    username: admin
    password: SomeSecretPassword
    vrf: vrf_lab
    tenant: lab_tenant
    state: absent
    leak_to:
      - vrf: "test2"
        tenant: "lab_tenant"
    description: Ansible Test
    ip: 1.1.1.2
  delegate_to: localhost

- name: Delete leak internal subnet
  cisco.aci.aci_vrf_leak_internal_subnet:
    host: apic
    username: admin
    password: SomeSecretPassword
    vrf: vrf_lab
    tenant: lab_tenant
    state: absent
    description: Ansible Test
    ip: 1.1.1.2
  delegate_to: localhost

- name: Query all leak internal subnet
  cisco.aci.aci_vrf_leak_internal_subnet:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
    ip: 1.1.1.2
  delegate_to: localhost
  register: query_result

- name: Query leak internal subnet
  cisco.aci.aci_vrf_leak_internal_subnet:
    host: apic
    username: admin
    password: SomeSecretPassword
    vrf: vrf_lab
    tenant: lab_tenant
    state: query
    ip: 1.1.1.2
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
        tenant=dict(type="str", aliases=["tenant_name"]),  # Not required for querying all objects
        vrf=dict(type="str", aliases=["context", "name", "vrf_name"]),  # Not required for querying all objects
        leak_to=dict(
            type="list",
            elements="dict",
            options=dict(
                vrf=dict(type="str", aliases=["vrf_name"]),
                tenant=dict(type="str", aliases=["tenant_name"]),
            ),
        ),
        description=dict(type="str", aliases=["descr"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        name_alias=dict(type="str"),
        scope=dict(type="str", default="private", choices=["public", "private", "shared"]),
        ip=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["tenant", "vrf"]],
            ["state", "present", ["tenant", "vrf", "leak_to"]],
        ],
    )

    description = module.params.get("description")
    state = module.params.get("state")
    tenant = module.params.get("tenant")
    vrf = module.params.get("vrf")
    leak_to = module.params.get("leak_to")
    name_alias = module.params.get("name_alias")
    scope = module.params.get("scope")
    ip = module.params.get("ip")

    aci = ACIModule(module)
    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter={"name": tenant},
        ),
        subclass_1=dict(
            aci_class="fvCtx",
            aci_rn="ctx-{0}".format(vrf),
            module_object=vrf,
            target_filter={"name": vrf},
        ),
        subclass_2=dict(
            aci_class="leakRoutes",
            aci_rn="leakroutes",
            module_object=True,
        ),
        subclass_3=dict(
            aci_class="leakInternalSubnet",
            aci_rn="leakintsubnet-[{0}]".format(ip),
            module_object=ip,
            target_filter={"ip": ip},
        ),
        child_classes=["leakTo"],
    )

    aci.get_existing()

    if state == "present":
        child_configs = []

        subnet_rn_list = []
        for subnet in leak_to:
            subnet_rn_list.append("to-[{0}]-[{1}]".format(subnet.get("tenant"), subnet.get("vrf")))
            child_configs.append(
                dict(
                    leakTo=dict(
                        attributes=dict(
                            ctxName=subnet.get("vrf"),
                            tenantName=subnet.get("tenant"),
                            scope=scope,
                        )
                    )
                )
            )

        if isinstance(aci.existing, list) and len(aci.existing) > 0:
            for child in aci.existing[0].get("leakInternalSubnet", {}).get("children", {}):
                child_attributes = child.get("leakTo", {}).get("attributes", {})
                if child_attributes and "to-[{0}]-[{1}]".format(child_attributes.get("tenantName"), child_attributes.get("ctxName")) not in subnet_rn_list:
                    child_configs.append(
                        dict(
                            leakTo=dict(
                                attributes=dict(
                                    ctxName=child_attributes.get("ctxName"),
                                    tenantName=child_attributes.get("tenantName"),
                                    status="deleted",
                                )
                            )
                        )
                    )

        aci.payload(
            aci_class="leakInternalSubnet",
            class_config=dict(
                descr=description,
                ip=ip,
                scope=scope,
                nameAlias=name_alias,
            ),
            child_configs=child_configs,
        )

        aci.get_diff(aci_class="leakInternalSubnet")

        if aci.existing:
            aci.post_config()
        else:
            aci.post_config(parent_class="leakRoutes")

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
