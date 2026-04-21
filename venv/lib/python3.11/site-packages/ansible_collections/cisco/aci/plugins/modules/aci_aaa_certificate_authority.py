#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Akini Ross (@akinross) <akinross@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_aaa_certificate_authority
short_description: Manage AAA Certificate Authorities (pki:TP)
description:
- Manage AAA Certificate Authorities on Cisco ACI fabrics.
options:
  name:
    description:
    - The name of the Certificate Authority.
    type: str
    aliases: [ certificate_authority, cert_authority, cert_authority_name, certificate_authority_name ]
  cloud_tenant:
    description:
    - The name of the cloud tenant.
    - This attribute is only applicable for Cloud APIC.
    type: str
    aliases: [ tenant, tenant_name ]
  description:
    description:
    - The description of the Certificate Authority.
    type: str
    aliases: [ descr ]
  certificate_chain:
    description:
    - The PEM-encoded chain of trust from the trustpoint to a trusted root authority.
    type: str
    aliases: [ cert_data, certificate_data, cert, certificate ]
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
- cisco.aci.owner

notes:
- The C(cloud_tenant) used must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant) module can be used for this.
seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(pki:TP).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Akini Ross (@akinross)
"""

EXAMPLES = r"""
- name: Create a Certificate Authority
  cisco.aci.aci_aaa_certificate_authority:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: example_authority
    certificate_chain: '{{ lookup("file", "pki/example_authority.crt") }}'
    state: present
  delegate_to: localhost

- name: Query a Certificate Authority
  cisco.aci.aci_aaa_certificate_authority:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: example_authority
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all Certificate Authorities
  cisco.aci.aci_aaa_certificate_authority:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

- name: Delete a Certificate Authority
  cisco.aci.aci_aaa_certificate_authority:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: example_authority
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
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec, aci_owner_spec


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        name=dict(
            type="str", aliases=["certificate_authority", "cert_authority", "cert_authority_name", "certificate_authority_name"]
        ),  # Not required for querying all objects
        cloud_tenant=dict(type="str", aliases=["tenant", "tenant_name"]),
        description=dict(type="str", aliases=["descr"]),
        certificate_chain=dict(type="str", aliases=["cert_data", "certificate_data", "cert", "certificate"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        name_alias=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["name"]],
            ["state", "present", ["name", "certificate_chain"]],
        ],
    )

    name = module.params.get("name")
    cloud_tenant = module.params.get("cloud_tenant")
    description = module.params.get("description")
    certificate_chain = module.params.get("certificate_chain")
    state = module.params.get("state")
    name_alias = module.params.get("name_alias")

    aci = ACIModule(module)
    aci_class = "pkiTP"
    parent_class = "cloudCertStore" if cloud_tenant else "pkiEp"
    parent_rn = "tn-{0}/certstore".format(cloud_tenant) if cloud_tenant else "userext/pkiext"

    aci.construct_url(
        root_class=dict(
            aci_class=parent_class,
            aci_rn=parent_rn,
        ),
        subclass_1=dict(
            aci_class=aci_class,
            aci_rn="tp-{0}".format(name),
            module_object=name,
            target_filter={"name": name},
        ),
    )
    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class=aci_class,
            class_config=dict(
                name=name,
                descr=description,
                certChain=certificate_chain,
                nameAlias=name_alias,
            ),
        )

        aci.get_diff(aci_class=aci_class)

        # Only wrap the payload in parent class if cloud_tenant is set to avoid apic error
        aci.post_config(parent_class=parent_class if cloud_tenant else None)

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
