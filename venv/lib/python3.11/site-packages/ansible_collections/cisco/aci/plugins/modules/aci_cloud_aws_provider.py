#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Shreyas Srish <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: aci_cloud_aws_provider
short_description: Manage Cloud AWS Provider (cloud:AwsProvider)
description:
- Manage AWS provider on Cisco Cloud ACI.
author:
- Shreyas Srish (@shrsr)
options:
  access_key_id:
    description:
    - Cloud Access Key ID.
    type: str
  account_id:
    description:
    - AWS Account ID.
    type: str
  is_account_in_org:
    description:
    - Is Account in Organization.
    type: bool
  is_trusted:
    description:
    - Trusted Tenant
    type: bool
  secret_access_key:
    description:
    - Cloud Secret Access Key.
    - Providing this option will always result in a change because it is a secure property that cannot be retrieved from APIC.
    type: str
  tenant:
    description:
    - Name of tenant.
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
  - More information about the internal APIC class B(cloud:AwsProvider) from
  - L(the APIC Management Information Model reference,https://developer.cisco.com/docs/apic-mim-ref/).
"""

EXAMPLES = r"""
- name: Create aws provider again after deletion as not trusted
  cisco.aci.aci_cloud_aws_provider:
    host: apic
    username: admin
    password: SomeSecretePassword
    tenant: ansible_test
    account_id: 111111111111
    is_trusted: true
    state: present
  delegate_to: localhost

- name: Delete aws provider
  cisco.aci.aci_cloud_aws_provider:
    host: apic
    username: admin
    password: SomeSecretePassword
    tenant: ansible_test
    account_id: 111111111111
    is_trusted: true
    state: absent
  delegate_to: localhost

- name: Query aws provider
  cisco.aci.aci_cloud_aws_provider:
    host: apic
    username: admin
    password: SomeSecretePassword
    state: query
  delegate_to: localhost

- name: Query all aws provider
  cisco.aci.aci_cloud_aws_provider:
    host: apic
    username: admin
    password: SomeSecretePassword
    state: query
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

from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec, aci_owner_spec
from ansible.module_utils.basic import AnsibleModule


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        {
            "access_key_id": dict(type="str"),
            "account_id": dict(type="str"),
            "is_account_in_org": dict(type="bool"),
            "is_trusted": dict(type="bool"),
            "secret_access_key": dict(type="str", no_log=True),
            "tenant": dict(type="str"),
            "state": dict(type="str", default="present", choices=["absent", "present", "query"]),
        }
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["tenant"]],
            ["state", "present", ["tenant"]],
        ],
    )

    aci = ACIModule(module)

    access_key_id = module.params.get("access_key_id")
    account_id = module.params.get("account_id")
    annotation = module.params.get("annotation")
    is_account_in_org = aci.boolean(module.params.get("is_account_in_org"))
    is_trusted = aci.boolean(module.params.get("is_trusted"))
    secret_access_key = module.params.get("secret_access_key")
    tenant = module.params.get("tenant")
    state = module.params.get("state")
    child_configs = []

    aci.construct_url(
        root_class={
            "aci_class": "fvTenant",
            "aci_rn": "tn-{0}".format(tenant),
            "target_filter": 'eq(fvTenant.name, "{0}")'.format(tenant),
            "module_object": tenant,
        },
        subclass_1={
            "aci_class": "cloudAwsProvider",
            "aci_rn": "awsprovider",
            "target_filter": {"account_id": account_id},
            "module_object": account_id,
        },
        child_classes=[],
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="cloudAwsProvider",
            class_config={
                "accessKeyId": access_key_id,
                "accountId": account_id,
                "annotation": annotation,
                "isAccountInOrg": is_account_in_org,
                "isTrusted": is_trusted,
                "secretAccessKey": secret_access_key,
            },
            child_configs=child_configs,
        )

        aci.get_diff(aci_class="cloudAwsProvider")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
