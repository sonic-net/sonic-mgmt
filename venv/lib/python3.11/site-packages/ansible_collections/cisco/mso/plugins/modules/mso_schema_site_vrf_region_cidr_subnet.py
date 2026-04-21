#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Anvitha Jain (@anvitha-jain) <anvjain@cisco.com>
# Copyright: (c) 2019, Dag Wieers (@dagwieers) <dag@wieers.com>
# Copyright: (c) 2020, Lionel Hercot (@lhercot) <lhercot@cisco.com>
# Copyright: (c) 2021, Anvitha Jain (@anvitha-jain) <anvjain@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_schema_site_vrf_region_cidr_subnet
short_description: Manage site-local VRF regions in schema template
description:
- Manage site-local VRF regions in schema template on Cisco ACI Multi-Site.
author:
- Dag Wieers (@dagwieers)
- Lionel Hercot (@lhercot)
- Anvitha Jain (@anvitha-jain)
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
  cidr:
    description:
    - The IP range of for the region CIDR.
    type: str
    required: true
  subnet:
    description:
    - The IP subnet of this region CIDR.
    type: str
    aliases: [ ip ]
  private_link_label:
    description:
    - The private link label used to represent this subnet.
    - This parameter is available for MSO version greater than 3.3.
    type: str
  zone:
    description:
    - The name of the zone for the region CIDR subnet.
    - This argument is required for AWS sites.
    type: str
    aliases: [ name ]
  vgw:
    description:
    - Whether this subnet is used for the Azure Gateway in Azure.
    - Whether this subnet is used for the Transit Gateway Attachment in AWS.
    type: bool
    aliases: [ hub_network ]
  hosted_vrf:
    description:
    - The name of hosted vrf associated with region CIDR subnet.
    - This is supported on versions of MSO that are 3.3 or greater.
    type: str
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
- module: cisco.mso.mso_schema_site_vrf_region_cidr
- module: cisco.mso.mso_schema_template_vrf
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Add a new site VRF region CIDR subnet
  cisco.mso.mso_schema_site_vrf_region_cidr_subnet:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    vrf: VRF1
    region: us-west-1
    cidr: 14.14.14.1/24
    subnet: 14.14.14.2/24
    zone: us-west-1a
    state: present

- name: Remove a site VRF region CIDR subnet
  cisco.mso.mso_schema_site_vrf_region_cidr_subnet:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    vrf: VRF1
    region: us-west-1
    cidr: 14.14.14.1/24
    subnet: 14.14.14.2/24
    state: absent

- name: Query a specific site VRF region CIDR subnet
  cisco.mso.mso_schema_site_vrf_region_cidr_subnet:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    vrf: VRF1
    region: us-west-1
    cidr: 14.14.14.1/24
    subnet: 14.14.14.2/24
    state: query
  register: query_result

- name: Query all site VRF region CIDR subnet
  cisco.mso.mso_schema_site_vrf_region_cidr_subnet:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    vrf: VRF1
    region: us-west-1
    cidr: 14.14.14.1/24
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
        region=dict(type="str", required=True),
        cidr=dict(type="str", required=True),
        subnet=dict(type="str", aliases=["ip"]),  # This parameter is not required for querying all objects
        private_link_label=dict(type="str"),
        zone=dict(type="str", aliases=["name"]),
        vgw=dict(type="bool", aliases=["hub_network"]),
        hosted_vrf=dict(type="str"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["subnet"]],
            ["state", "present", ["subnet"]],
        ],
    )

    schema = module.params.get("schema")
    site = module.params.get("site")
    template = module.params.get("template").replace(" ", "")
    vrf = module.params.get("vrf")
    region = module.params.get("region")
    cidr = module.params.get("cidr")
    subnet = module.params.get("subnet")
    private_link_label = module.params.get("private_link_label")
    zone = module.params.get("zone")
    hosted_vrf = module.params.get("hosted_vrf")
    vgw = module.params.get("vgw")
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
    sites_list = [s.get("siteId") + "/" + s.get("templateName") for s in schema_obj.get("sites")]
    if (site_id, template) not in sites:
        mso.fail_json(
            msg="Provided site/siteId/template '{0}/{1}/{2}' does not exist. "
            "Existing siteIds/templates: {3}".format(site, site_id, template, ", ".join(sites_list))
        )

    # Schema-access uses indexes
    site_idx = sites.index((site_id, template))
    # Path-based access uses site_id-template
    site_template = "{0}-{1}".format(site_id, template)

    # Get VRF at site level
    vrf_ref = mso.vrf_ref(schema_id=schema_id, template=template, vrf=vrf)
    vrfs = [v.get("vrfRef") for v in schema_obj.get("sites")[site_idx]["vrfs"]]

    # If vrf not at site level but exists at template level
    if vrf_ref not in vrfs:
        mso.fail_json(msg="Provided vrf '{0}' does not exist at site level." " Use mso_schema_site_vrf_region_cidr to create it.".format(vrf))
    vrf_idx = vrfs.index(vrf_ref)

    # Get Region
    regions = [r.get("name") for r in schema_obj.get("sites")[site_idx]["vrfs"][vrf_idx]["regions"]]
    if region not in regions:
        mso.fail_json(
            msg="Provided region '{0}' does not exist. Existing regions: {1}."
            " Use mso_schema_site_vrf_region_cidr to create it.".format(region, ", ".join(regions))
        )
    region_idx = regions.index(region)

    # Get CIDR
    cidrs = [c.get("ip") for c in schema_obj.get("sites")[site_idx]["vrfs"][vrf_idx]["regions"][region_idx]["cidrs"]]
    if cidr not in cidrs:
        mso.fail_json(
            msg="Provided CIDR IP '{0}' does not exist. Existing CIDR IPs: {1}."
            " Use mso_schema_site_vrf_region_cidr to create it.".format(cidr, ", ".join(cidrs))
        )
    cidr_idx = cidrs.index(cidr)

    # Get Subnet
    subnets = [s.get("ip") for s in schema_obj.get("sites")[site_idx]["vrfs"][vrf_idx]["regions"][region_idx]["cidrs"][cidr_idx]["subnets"]]
    if subnet is not None and subnet in subnets:
        subnet_idx = subnets.index(subnet)
        # FIXME: Changes based on index are DANGEROUS
        subnet_path = "/sites/{0}/vrfs/{1}/regions/{2}/cidrs/{3}/subnets/{4}".format(site_template, vrf, region, cidr_idx, subnet_idx)
        mso.existing = schema_obj.get("sites")[site_idx]["vrfs"][vrf_idx]["regions"][region_idx]["cidrs"][cidr_idx]["subnets"][subnet_idx]

    if state == "query":
        if subnet is None:
            mso.existing = schema_obj.get("sites")[site_idx]["vrfs"][vrf_idx]["regions"][region_idx]["cidrs"][cidr_idx]["subnets"]
        elif not mso.existing:
            mso.fail_json(msg="Subnet IP '{subnet}' not found".format(subnet=subnet))
        mso.exit_json()

    subnets_path = "/sites/{0}/vrfs/{1}/regions/{2}/cidrs/{3}/subnets".format(site_template, vrf, region, cidr_idx)
    ops = []

    mso.previous = mso.existing
    if state == "absent":
        if mso.existing:
            mso.sent = mso.existing = {}
            ops.append(dict(op="remove", path=subnet_path))

    elif state == "present":
        payload = dict(ip=subnet, zone="")

        if zone is not None:
            payload["zone"] = zone
        if vgw is True:
            payload["usage"] = "gateway"
        if private_link_label is not None:
            payload["privateLinkLabel"] = dict(name=private_link_label)
        if hosted_vrf is not None:
            payload["vrfRef"] = dict(schemaId=schema_id, templateName=template, vrfName=hosted_vrf)
            payload["inEditing"] = "false"

        mso.sanitize(payload, collate=True)

        if mso.existing:
            ops.append(dict(op="replace", path=subnet_path, value=mso.sent))
        else:
            ops.append(dict(op="add", path=subnets_path + "/-", value=mso.sent))

        mso.existing = mso.proposed

    if not module.check_mode:
        mso.request(schema_path, method="PATCH", data=ops)

    mso.exit_json()


if __name__ == "__main__":
    main()
