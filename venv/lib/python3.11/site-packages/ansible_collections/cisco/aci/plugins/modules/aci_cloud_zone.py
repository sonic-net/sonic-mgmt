#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, nkatarmal-crest <nirav.katarmal@crestdatasys.com>
# Copyright: (c) 2020, Cindy Zhao <cizhao@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: aci_cloud_zone
short_description: Manage Cloud Availability Zone (cloud:Zone)
description:
-  Manage Cloud Availability Zone on Cisco Cloud ACI.
notes:
- More information about the internal APIC class B(cloud:Zone) from
  L(the APIC Management Information Model reference,https://developer.cisco.com/docs/apic-mim-ref/).
- This module is used to query Cloud Availability Zone.
author:
- Nirav (@nirav)
- Cindy Zhao (@cizhao)
options:
  name:
    description:
    - object name
    aliases: [ zone ]
    type: str
  cloud:
    description:
    - The cloud provider.
    choices: [ aws, azure ]
    type: str
    required: true
  region:
    description:
    - The name of the cloud provider's region.
    type: str
    required: true
  state:
    description:
    - Use C(query) for listing an object or multiple objects.
    choices: [ query ]
    default: query
    type: str
extends_documentation_fragment:
- cisco.aci.aci
- cisco.aci.annotation
"""

EXAMPLES = r"""
- name: Query all zones in a region
  cisco.aci.aci_cloud_zone:
    host: apic
    username: userName
    password: somePassword
    validate_certs: false
    cloud: 'aws'
    region: regionName
    state: query
  delegate_to: localhost

- name: Query a specific zone
  cisco.aci.aci_cloud_zone:
    host: apic
    username: userName
    password: somePassword
    validate_certs: false
    cloud: 'aws'
    region: regionName
    zone: zoneName
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

from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec
from ansible.module_utils.basic import AnsibleModule


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(
        name=dict(type="str", aliases=["zone"]),
        cloud=dict(type="str", choices=["aws", "azure"], required=True),
        region=dict(type="str", required=True),
        state=dict(type="str", default="query", choices=["query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    name = module.params.get("name")
    cloud = module.params.get("cloud")
    region = module.params.get("region")

    aci = ACIModule(module)
    aci.construct_url(
        root_class=dict(
            aci_class="cloudProvP", aci_rn="clouddomp/provp-{0}".format(cloud), target_filter='eq(cloudProvP.vendor, "{0}")'.format(cloud), module_object=cloud
        ),
        subclass_1=dict(
            aci_class="cloudRegion", aci_rn="region-{0}".format(region), target_filter='eq(cloudRegion.name, "{0}")'.format(region), module_object=region
        ),
        subclass_2=dict(aci_class="cloudZone", aci_rn="zone-{0}".format(name), target_filter='eq(cloudZone.name, "{0}")'.format(name), module_object=name),
        child_classes=[],
    )

    aci.get_existing()

    aci.exit_json()


if __name__ == "__main__":
    main()
