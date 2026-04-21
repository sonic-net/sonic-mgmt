#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_vmm_uplink_container
short_description: Manage VMM uplink containers (vmm:UplinkPCont)
description:
- Manage VMM Uplink containers on Cisco ACI fabrics.
- Individual uplinks within the container are managed using the M(cisco.aci.aci_vmm_uplink) module
options:
  domain:
    description:
    - Name of the VMM domain
    type: str
  num_of_uplinks:
    description:
    - Number of uplinks in the container
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
- The C(domain) used must exist before using this module in your playbook.
  The M(cisco.aci.aci_domain) module can be used for this.
seealso:
- module: cisco.aci.aci_tenant
- module: cisco.aci.aci_domain
- module: cisco.aci.aci_vrf
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(vmm:UplinkPCont).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
"""

EXAMPLES = r"""
- name: Add a new uplink container
  cisco.aci.aci_vmm_uplink_container:
    host: apic
    username: admin
    password: SomeSecretPassword
    domain: my_vmm_domain
    num_of_uplinks: 2
    state: present
  delegate_to: localhost

- name: Delete uplink container
  cisco.aci.aci_vmm_uplink_container:
    host: apic
    username: admin
    password: SomeSecretPassword
    domain: my_vmm_domain
    state: absent
  delegate_to: localhost

- name: Query uplink container
  cisco.aci.aci_vmm_uplink_container:
    host: apic
    username: admin
    password: SomeSecretPassword
    domain: my_vmm_domain
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
        domain=dict(type="str"),
        num_of_uplinks=dict(type="int"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["domain"]],
            ["state", "present", ["domain", "num_of_uplinks"]],
        ],
    )

    domain = module.params.get("domain")
    num_of_uplinks = module.params.get("num_of_uplinks")
    state = module.params.get("state")

    aci = ACIModule(module)

    aci.construct_url(
        root_class=dict(
            aci_class="vmmProvP",
            aci_rn="vmmp-VMware",
            module_object="VMware",
            target_filter={"name": "VMware"},
        ),
        subclass_1=dict(
            aci_class="vmmDomP",
            aci_rn="dom-{0}".format(domain),
            module_object=domain,
            target_filter={"name": domain},
        ),
        subclass_2=dict(
            aci_class="vmmUplinkPCont",
            aci_rn="uplinkpcont",
            module_object="uplinkpcont",
            target_filter={"rn": "uplinkpcont"},
        ),
        child_classes=["vmmUplinkP"],
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="vmmUplinkPCont",
            class_config=dict(
                numOfUplinks=num_of_uplinks,
            ),
        )

        aci.get_diff(aci_class="vmmUplinkPCont")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
