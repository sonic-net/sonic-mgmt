#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2019, Dag Wieers (@dagwieers) <dag@wieers.com>
# Copyright: (c) 2021, Anvitha Jain (@anvitha-jain) <anvjain@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_schema_site_vrf_region
short_description: Manage site-local VRF regions in schema template
description:
- Manage site-local VRF regions in schema template on Cisco ACI Multi-Site.
author:
- Anvitha Jain (@anvitha-jain)
- Dag Wieers (@dagwieers)
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
    - The name of the region to manage.
    type: str
    aliases: [ name ]
  vpn_gateway_router:
    description:
    - Whether VPN Gateway Router is enabled or not.
    type: bool
  container_overlay:
    description:
    - The name of the context profile type.
    - This is supported on versions of MSO that are 3.3 or greater.
    type: bool
  underlay_context_profile:
    description:
    - The name of the context profile type.
    - This parameter can only be added when container_overlay is True.
    - This is supported on versions of MSO that are 3.3 or greater.
    type: dict
    suboptions:
      vrf:
        description:
        - The name of the VRF to associate with underlay context profile.
        type: str
        required: true
      region:
        description:
        - The name of the region associated with underlay context profile VRF.
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
- Due to restrictions of the MSO REST API, this module cannot create empty region (i.e. regions without cidrs)
  Use the M(cisco.mso.mso_schema_site_vrf_region_cidr) to automatically create regions with cidrs.
seealso:
- module: cisco.mso.mso_schema_site_vrf
- module: cisco.mso.mso_schema_template_vrf
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Remove VPN Gateway Router at site VRF Region
  cisco.mso.mso_schema_site_vrf_region:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    vrf: VRF1
    region: us-west-1
    vpn_gateway_router: false
    state: present

- name: Remove a site VRF region
  cisco.mso.mso_schema_site_vrf_region:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    vrf: VRF1
    region: us-west-1
    state: absent

- name: Query a specific site VRF region
  cisco.mso.mso_schema_site_vrf_region:
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

- name: Query all site VRF regions
  cisco.mso.mso_schema_site_vrf_region:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    vrf: VRF1
    state: query
  register: query_result
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        schema=dict(type="str", required=True),
        site=dict(type="str", required=True),
        template=dict(type="str", required=True),
        vrf=dict(type="str", required=True),
        region=dict(type="str", aliases=["name"]),  # This parameter is not required for querying all objects
        vpn_gateway_router=dict(type="bool"),
        container_overlay=dict(type="bool"),
        underlay_context_profile=dict(
            type="dict",
            options=dict(
                vrf=dict(type="str", required=True),
                region=dict(type="str", required=True),
            ),
        ),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["region"]],
            ["state", "present", ["region"]],
        ],
    )

    schema = module.params.get("schema")
    site = module.params.get("site")
    template = module.params.get("template").replace(" ", "")
    vrf = module.params.get("vrf")
    region = module.params.get("region")
    vpn_gateway_router = module.params.get("vpn_gateway_router")
    container_overlay = module.params.get("container_overlay")
    underlay_context_profile = module.params.get("underlay_context_profile")
    state = module.params.get("state")

    mso = MSOModule(module)

    # Get schema objects
    schema_id, schema_path, schema_obj = mso.query_schema(schema)

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
    if region is not None and region in regions:
        region_idx = regions.index(region)
        region_path = "/sites/{0}/vrfs/{1}/regions/{2}".format(site_template, vrf, region)
        mso.existing = schema_obj.get("sites")[site_idx]["vrfs"][vrf_idx]["regions"][region_idx]

    if state == "query":
        if region is None:
            mso.existing = schema_obj.get("sites")[site_idx]["vrfs"][vrf_idx]["regions"]
        elif not mso.existing:
            mso.fail_json(msg="Region '{region}' not found".format(region=region))
        mso.exit_json()

    regions_path = "/sites/{0}/vrfs/{1}/regions".format(site_template, vrf)
    ops = []

    mso.previous = mso.existing
    if state == "absent":
        if mso.existing:
            mso.sent = mso.existing = {}
            ops.append(dict(op="remove", path=region_path))

    elif state == "present":
        payload = dict(
            name=region,
            isVpnGatewayRouter=vpn_gateway_router,
        )

        if container_overlay:
            payload["contextProfileType"] = "container-overlay"
            if mso.existing:
                underlay_dict = dict(
                    vrfRef=dict(schemaId=schema_id, templateName=template, vrfName=underlay_context_profile["vrf"]),
                    regionName=underlay_context_profile["region"],
                )
                payload["underlayCtxProfile"] = underlay_dict

        mso.sanitize(payload, collate=True)
        if mso.existing:
            ops.append(dict(op="replace", path=region_path, value=mso.sent))
        else:
            ops.append(dict(op="add", path=regions_path + "/-", value=mso.sent))

        mso.existing = mso.proposed

    if not module.check_mode:
        mso.request(schema_path, method="PATCH", data=ops)

    mso.exit_json()


if __name__ == "__main__":
    main()
