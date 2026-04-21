#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Cindy Zhao (@cizhao) <cizhao@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_schema_site_vrf_region_hub_network
short_description: Manage site-local VRF region hub network in schema template
description:
- Manage site-local VRF region hub network in schema template on Cisco ACI Multi-Site.
- The 'Hub Network' feature was introduced in Multi-Site Orchestrator (MSO) version 3.0(1) for AWS and version 3.0(2) for Azure.
author:
- Cindy Zhao (@cizhao)
options:
  schema:
    description:
    - The name of the schema.
    type: str
    required: true
  site:
    description:
    - The name of the site.
    type: str
    required: true
  template:
    description:
    - The name of the template.
    type: str
    required: true
  vrf:
    description:
    - The name of the VRF.
    type: str
    required: true
  region:
    description:
    - The name of the region.
    type: str
    required: true
  hub_network:
    description:
    - The hub network to be managed.
    type: dict
    suboptions:
      name:
        description:
        - The name of the hub network.
        - The hub-default is the default created hub network.
        type: str
        required: true
      tenant:
        description:
        - The tenant name of the hub network.
        type: str
        required: true
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
notes:
- The ACI MultiSite PATCH API has a deficiency requiring some objects to be referenced by index.
  This can cause silent corruption on concurrent access when changing/removing on object as
  the wrong object may be referenced. This module is affected by this deficiency.
seealso:
- module: cisco.mso.mso_schema_site_vrf_region
- module: cisco.mso.mso_schema_template_vrf
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Add a new site VRF region hub network
  cisco.mso.mso_schema_site_vrf_region_hub_network:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    vrf: VRF1
    region: us-west-1
    hub_network:
      name: hub-default
      tenant: infra
    state: present

- name: Remove a site VRF region hub network
  cisco.mso.mso_schema_site_vrf_region_hub_network:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    vrf: VRF1
    state: absent

- name: Query site VRF region hub network
  cisco.mso.mso_schema_site_vrf_region_hub_network:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    vrf: VRF1
    region: us-west-1
    state: query
  register: query_result
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec, mso_hub_network_spec


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        schema=dict(type="str", required=True),
        site=dict(type="str", required=True),
        template=dict(type="str", required=True),
        vrf=dict(type="str", required=True),
        region=dict(type="str", required=True),
        hub_network=dict(type="dict", options=mso_hub_network_spec()),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "present", ["hub_network"]],
        ],
    )

    schema = module.params.get("schema")
    site = module.params.get("site")
    template = module.params.get("template").replace(" ", "")
    vrf = module.params.get("vrf")
    region = module.params.get("region")
    hub_network = module.params.get("hub_network")
    state = module.params.get("state")

    mso = MSOModule(module)

    # Get schema objects
    schema_id, schema_path, schema_obj = mso.query_schema(schema)

    # Get template
    templates = [t.get("name") for t in schema_obj.get("templates")]
    if template not in templates:
        mso.fail_json(msg="Provided template '{0}' does not exist. Existing templates: {1}".format(template, ", ".join(templates)))

    # Get site
    site_id = mso.lookup_site(site)

    # Get site_idx
    if not schema_obj.get("sites"):
        mso.fail_json(msg="No site associated with template '{0}'. Associate the site with the template using mso_schema_site.".format(template))
    sites = [(s.get("siteId"), s.get("templateName")) for s in schema_obj.get("sites")]
    if (site_id, template) not in sites:
        mso.fail_json(msg="Provided site-template association '{0}-{1}' does not exist.".format(site, template))

    # Schema-access uses indexes
    site_idx = sites.index((site_id, template))
    # Path-based access uses site_id-template
    site_template = "{0}-{1}".format(site_id, template)

    # Get VRF
    vrf_ref = mso.vrf_ref(schema_id=schema_id, template=template, vrf=vrf)
    vrfs = [v.get("vrfRef") for v in schema_obj.get("sites")[site_idx]["vrfs"]]
    vrfs_name = [mso.dict_from_ref(v).get("vrfName") for v in vrfs]
    if vrf_ref not in vrfs:
        mso.fail_json(msg="Provided vrf '{0}' does not exist. Existing vrfs: {1}".format(vrf, ", ".join(vrfs_name)))
    vrf_idx = vrfs.index(vrf_ref)

    # Get Region
    regions = [r.get("name") for r in schema_obj.get("sites")[site_idx]["vrfs"][vrf_idx]["regions"]]
    if region not in regions:
        mso.fail_json(msg="Provided region '{0}' does not exist. Existing regions: {1}".format(region, ", ".join(regions)))
    region_idx = regions.index(region)
    # Get Region object
    region_obj = schema_obj.get("sites")[site_idx]["vrfs"][vrf_idx]["regions"][region_idx]
    region_path = "/sites/{0}/vrfs/{1}/regions/{2}".format(site_template, vrf, region)

    # Get hub network
    existing_hub_network = region_obj.get("cloudRsCtxProfileToGatewayRouterP")
    if existing_hub_network is not None:
        mso.existing = existing_hub_network

    if state == "query":
        if not mso.existing:
            mso.fail_json(msg="Hub network not found")
        mso.exit_json()

    ops = []

    mso.previous = mso.existing
    if state == "absent":
        if mso.existing:
            mso.sent = mso.existing = {}
            ops.append(dict(op="remove", path=region_path + "/cloudRsCtxProfileToGatewayRouterP"))
            ops.append(dict(op="replace", path=region_path + "/isTGWAttachment", value=False))

    elif state == "present":
        new_hub_network = dict(
            name=hub_network.get("name"),
            tenantName=hub_network.get("tenant"),
        )
        payload = region_obj
        payload.update(
            cloudRsCtxProfileToGatewayRouterP=new_hub_network,
            isTGWAttachment=True,
        )

        mso.sanitize(payload, collate=True)

        ops.append(dict(op="replace", path=region_path, value=mso.sent))

        mso.existing = new_hub_network

    if not module.check_mode and mso.previous != mso.existing:
        mso.request(schema_path, method="PATCH", data=ops)

    mso.exit_json()


if __name__ == "__main__":
    main()
