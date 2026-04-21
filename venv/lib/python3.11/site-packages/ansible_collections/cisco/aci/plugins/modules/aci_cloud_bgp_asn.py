#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Anvitha Jain (@anvitha-jain) <anvjain@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: aci_cloud_bgp_asn
short_description: Manage Cloud APIC BGP Autonomous System Profile (cloud:BgpAsP)
description:
- Manage the BGP Autonomous System Profile for Cloud APIC
author:
- Anvitha Jain (@anvitha-jain)
version_added: '2.1.0'
options:
  asn:
    description:
    - The BGP Autonomous System Number.
    type: str
  description:
    description:
    - Description of the BGP Autonomous System Profile.
    aliases: [ descr ]
    type: str
  name:
    description:
    - object name
    aliases: [ autonomous_system_profile, autonomous_system_profile_name ]
    type: str
  name_alias:
    description:
    - The alias for the current object. This relates to the nameAlias field in ACI.
    type: str
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    choices: [ absent, present, query ]
    default: present
    type: str
extends_documentation_fragment:
- cisco.aci.aci
- cisco.aci.annotation

notes:
- More information about the internal APIC class B(cloud:BgpAsP) from
  L(the APIC Management Information Model reference,https://developer.cisco.com/docs/apic-mim-ref/).
"""

EXAMPLES = r"""
- name: Add a new cloud BGP ASN
  cisco.aci.aci_cloud_bgp_asn:
    host: apic
    username: admin
    password: SomeSecretPassword
    asn: 64601
    description: ASN description
    name: ASN_1
    state: present
  delegate_to: localhost
- name: Remove a cloud BGP ASN
  cisco.aci.aci_cloud_bgp_asn:
    host: apic
    username: admin
    password: SomeSecretPassword
    validate_certs: false
    state: absent
  delegate_to: localhost
- name: Query a cloud BGP ASN
  cisco.aci.aci_cloud_bgp_asn:
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
        {
            "asn": dict(type="str"),
            "description": dict(type="str", aliases=["descr"]),
            "name": dict(type="str", aliases=["autonomous_system_profile", "autonomous_system_profile_name"]),
            "name_alias": dict(type="str"),
            "state": dict(type="str", default="present", choices=["absent", "present", "query"]),
        }
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    annotation = module.params["annotation"]
    asn = module.params["asn"]
    description = module.params["description"]
    name = module.params["name"]
    name_alias = module.params["name_alias"]
    state = module.params["state"]
    child_configs = []

    aci = ACIModule(module)
    aci.construct_url(
        root_class={"aci_class": "cloudBgpAsP", "aci_rn": "clouddomp/as", "target_filter": {"name": name}, "module_object": None}, child_classes=[]
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="cloudBgpAsP",
            class_config={
                "annotation": annotation,
                "asn": asn,
                "descr": description,
                "name": name,
                "nameAlias": name_alias,
            },
            child_configs=child_configs,
        )

        aci.get_diff(aci_class="cloudBgpAsP")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
