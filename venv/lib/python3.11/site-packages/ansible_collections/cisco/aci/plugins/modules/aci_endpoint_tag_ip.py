#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Sabari Jaganathan <sajagana@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_endpoint_tag_ip
short_description: Manage Endpoint Tag IP (fv:EpIpTag)
description:
- Manage Endpoint Tag IP on Cisco ACI fabrics.
options:
  tenant:
    description:
    - The name of the Tenant.
    type: str
  ip:
    description:
    - The IPv4 or IPv6 address of the Endpoint Tag IP.
    type: str
    aliases: [ ip_address, endpoint_ip_address ]
  vrf:
    description:
    - The name of the VRF.
    type: str
    aliases: [ vrf_name ]
  name_alias:
    description:
    - The alias for the current object. This relates to the nameAlias field in ACI.
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
- The O(tenant) and O(vrf) used must exist before using this module in your playbook.
- The M(cisco.aci.aci_tenant) and M(cisco.aci.aci_vrf) modules can be used for this.
seealso:
- module: cisco.aci.aci_tenant
- module: cisco.aci.aci_vrf
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(fv:EpIpTag).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Sabari Jaganathan (@sajagana)
"""

EXAMPLES = r"""
- name: Add an IP Tag
  cisco.aci.aci_endpoint_tag_ip:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: endpoint_tenant
    ip: 1.1.1.1
    vrf: endpoint_vrf
    name_alias: endpoint_ip_tag
    state: present

- name: Update an IP Tag
  cisco.aci.aci_endpoint_tag_ip:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: endpoint_tenant
    ip: 1.1.1.1
    vrf: endpoint_vrf
    name_alias: endpoint_ip_tag_updated
    state: present

- name: Query an IP Tag with specific IP and VRF
  cisco.aci.aci_endpoint_tag_ip:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: endpoint_tenant
    ip: 1.1.1.1
    vrf: endpoint_vrf
    state: query
  register: query_one

- name: Query all IP Tag Objects with only VRF
  cisco.aci.aci_endpoint_tag_ip:
    host: apic
    username: admin
    password: SomeSecretPassword
    vrf: default
    state: query
  register: query_with_vrf

- name: Query all IP Tag Objects with only IP
  cisco.aci.aci_endpoint_tag_ip:
    host: apic
    username: admin
    password: SomeSecretPassword
    ip: 1.1.1.1
    state: query
  register: query_with_ip

- name: Query all IP Tags
  cisco.aci.aci_endpoint_tag_ip:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  register: query_all

- name: Delete an IP Tag
  cisco.aci.aci_endpoint_tag_ip:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: endpoint_tenant
    ip: 1.1.1.1
    vrf: endpoint_vrf
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

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec, aci_owner_spec


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        tenant=dict(type="str"),
        ip=dict(type="str", aliases=["ip_address", "endpoint_ip_address"]),
        vrf=dict(type="str", aliases=["vrf_name"]),
        name_alias=dict(type="str"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["tenant", "vrf", "ip"]],
            ["state", "present", ["tenant", "vrf", "ip"]],
        ],
    )

    aci = ACIModule(module)

    tenant = module.params.get("tenant")
    ip = module.params.get("ip")
    vrf = module.params.get("vrf")
    name_alias = module.params.get("name_alias")
    annotation = module.params.get("annotation")
    state = module.params.get("state")

    aci = ACIModule(module)

    if ip and vrf:
        endpoint_ip_tag_module_object = "[{0}]-{1}".format(ip, vrf)
        endpoint_ip_tag_rn = "eptags/epiptag-{0}".format(endpoint_ip_tag_module_object)
    else:
        endpoint_ip_tag_rn = None
        endpoint_ip_tag_module_object = None

    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter={"name": tenant},
        ),
        subclass_1=dict(
            aci_class="fvEpIpTag",
            aci_rn=endpoint_ip_tag_rn,
            module_object=endpoint_ip_tag_module_object,
            target_filter=dict(ip=ip, ctxName=vrf),
        ),
    )
    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="fvEpIpTag",
            class_config=dict(
                annotation=annotation,
                ctxName=vrf,
                ip=ip,
                nameAlias=name_alias,
            ),
        )

        aci.get_diff(aci_class="fvEpIpTag")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
