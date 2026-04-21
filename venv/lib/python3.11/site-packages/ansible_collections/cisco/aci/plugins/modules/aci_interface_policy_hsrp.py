#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_interface_policy_hsrp
short_description: Manage HSRP interface policies (hsrp:IfPol)
description:
- Manage HSRP interface policies on Cisco ACI fabrics.
options:
  tenant:
    description:
    - The name of the Tenant the HSRP interface policy should belong to.
    type: str
    aliases: [ tenant_name ]
  hsrp:
    description:
    - The HSRP interface policy name.
    type: str
    aliases: [ hsrp_interface, name ]
  description:
    description:
    - The description of the HSRP interface.
    type: str
    aliases: [ descr ]
  controls:
    description:
    - The interface policy controls.
    type: list
    elements: str
    choices: [ bfd, bia ]
  delay:
    description:
    - The administrative port delay of HSRP interface policy.
    - This is only valid in range between 1 and 10000.
    type: int
  reload_delay:
    description:
    - The option for reload delay of HSRP interface policy.
    - This is only valid in range between 1 and 10000.
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
- cisco.aci.owner

notes:
- The C(tenant) must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant) can be used for this.
seealso:
- module: cisco.aci.aci_tenant
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(hsrp:IfPol).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Shreyas Srish (@shrsr)
"""

EXAMPLES = r"""
- name: Add a HSRP interface policy
  cisco.aci.aci_interface_policy_hsrp:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    hsrp: hsrp1
    controls: bfd
    delay: 50
    reload_delay: 100
    state: present
  delegate_to: localhost

- name: Delete a HSRP interface policy
  cisco.aci.aci_interface_policy_hsrp:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    hsrp: hsrp1
    state: absent
  delegate_to: localhost

- name: Query a HSRP interface policy
  cisco.aci.aci_interface_policy_hsrp:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    hsrp: hsrp1
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all HSRP interface policies in tenant production
  cisco.aci.aci_interface_policy_hsrp:
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
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec, aci_owner_spec


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        tenant=dict(type="str", aliases=["tenant_name"]),  # Not required for querying all objects
        hsrp=dict(type="str", aliases=["hsrp_interface", "name"]),  # Not required for querying all objects
        description=dict(type="str", aliases=["descr"]),
        controls=dict(type="list", elements="str", choices=["bfd", "bia"]),
        reload_delay=dict(type="int"),
        delay=dict(type="int"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["tenant", "hsrp"]],
            ["state", "present", ["tenant", "hsrp"]],
        ],
    )

    aci = ACIModule(module)

    tenant = module.params.get("tenant")
    hsrp = module.params.get("hsrp")
    description = module.params.get("description")
    controls = ",".join(module.params.get("controls")) if module.params.get("controls") else None

    reload_delay = module.params.get("reload_delay")
    if reload_delay is not None and reload_delay not in range(1, 10000):
        module.fail_json(msg="Parameter 'reload_delay' is only valid in range between 1 and 10000.")

    delay = module.params.get("delay")
    if delay is not None and delay not in range(1, 10000):
        module.fail_json(msg="Parameter 'delay' is only valid in range between 1 and 10000.")

    state = module.params.get("state")

    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter={"name": tenant},
        ),
        subclass_1=dict(
            aci_class="hsrpIfPol",
            aci_rn="hsrpIfPol-{0}".format(hsrp),
            module_object=hsrp,
            target_filter={"name": hsrp},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="hsrpIfPol",
            class_config=dict(
                name=hsrp,
                descr=description,
                ctrl=controls,
                reloadDelay=reload_delay,
                delay=delay,
            ),
        )

        aci.get_diff(aci_class="hsrpIfPol")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
