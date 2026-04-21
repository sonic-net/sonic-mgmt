#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Dag Wieers (dagwieers) <dag@wieers.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_aaa_user_certificate
short_description: Manage AAA user certificates (aaa:UserCert)
description:
- Manage AAA user certificates on Cisco ACI fabrics.
options:
  aaa_user:
    description:
    - The name of the user to add a certificate to.
    type: str
    required: true
  aaa_user_type:
    description:
    - Whether this is a normal user or an appuser.
    type: str
    choices: [ appuser, user ]
    default: user
  certificate:
    description:
    - The PEM format public key extracted from the X.509 certificate.
    type: str
    aliases: [ cert_data, certificate_data ]
  name:
    description:
    - The name of the user certificate entry in ACI.
    type: str
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
- The C(aaa_user) must exist before using this module in your playbook.
  The M(cisco.aci.aci_aaa_user) module can be used for this.
seealso:
- module: cisco.aci.aci_aaa_user
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(aaa:UserCert).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Dag Wieers (@dagwieers)
"""

EXAMPLES = r"""
- name: Add a certificate to user
  cisco.aci.aci_aaa_user_certificate:
    host: apic
    username: admin
    password: SomeSecretPassword
    aaa_user: admin
    name: admin
    certificate_data: '{{ lookup("file", "pki/admin.crt") }}'
    state: present
  delegate_to: localhost

- name: Remove a certificate of a user
  cisco.aci.aci_aaa_user_certificate:
    host: apic
    username: admin
    password: SomeSecretPassword
    aaa_user: admin
    name: admin
    state: absent
  delegate_to: localhost

- name: Query a certificate of a user
  cisco.aci.aci_aaa_user_certificate:
    host: apic
    username: admin
    password: SomeSecretPassword
    aaa_user: admin
    name: admin
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all certificates of a user
  cisco.aci.aci_aaa_user_certificate:
    host: apic
    username: admin
    password: SomeSecretPassword
    aaa_user: admin
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

ACI_MAPPING = dict(
    appuser=dict(
        aci_class="aaaAppUser",
        aci_mo="userext/appuser-",
    ),
    user=dict(
        aci_class="aaaUser",
        aci_mo="userext/user-",
    ),
)


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        aaa_user=dict(type="str", required=True),
        aaa_user_type=dict(type="str", default="user", choices=["appuser", "user"]),
        certificate=dict(type="str", aliases=["cert_data", "certificate_data"]),
        name=dict(type="str"),  # Not required for querying all objects
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        name_alias=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["aaa_user", "name"]],
            ["state", "present", ["aaa_user", "certificate", "name"]],
        ],
    )

    aaa_user = module.params.get("aaa_user")
    aaa_user_type = module.params.get("aaa_user_type")
    certificate = module.params.get("certificate")
    name = module.params.get("name")
    state = module.params.get("state")
    name_alias = module.params.get("name_alias")

    aci = ACIModule(module)
    aci.construct_url(
        root_class=dict(
            aci_class=ACI_MAPPING.get(aaa_user_type).get("aci_class"),
            aci_rn=ACI_MAPPING.get(aaa_user_type).get("aci_mo") + aaa_user,
            module_object=aaa_user,
            target_filter={"name": aaa_user},
        ),
        subclass_1=dict(
            aci_class="aaaUserCert",
            aci_rn="usercert-{0}".format(name),
            module_object=name,
            target_filter={"name": name},
        ),
    )
    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="aaaUserCert",
            class_config=dict(
                data=certificate,
                name=name,
                nameAlias=name_alias,
            ),
        )

        aci.get_diff(aci_class="aaaUserCert")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
