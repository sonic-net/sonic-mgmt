#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2019, Nirav Katarmal (@nkatarmal-crest) <nirav.katarmal@crestdatasys.com>
# Copyright: (c) 2023, Mabille Florent (@fmabille09) <florent.mabille@smals.be>
# Copyright: (c) 2024, Akini Ross (@akinross) <akinross@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_schema_site_anp_epg_domain
short_description: Manage site-local EPG domains in schema template
description:
- Manage site-local EPG domains in schema template on Cisco ACI Multi-Site.
author:
- Nirav Katarmal (@nkatarmal-crest)
- Mabille Florent (@fmabille09)
- Akini Ross (@akinross)
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
  anp:
    description:
    - The name of the ANP.
    type: str
    required: true
  epg:
    description:
    - The name of the EPG.
    type: str
    required: true
  domain_association_type:
    description:
    - The type of domain to associate.
    type: str
    choices: [ vmmDomain, l3ExtDomain, l2ExtDomain, physicalDomain, fibreChannelDomain ]
  domain_profile:
    description:
    - The domain profile name.
    type: str
  deployment_immediacy:
    description:
    - The deployment immediacy of the domain.
    - C(immediate) means B(Deploy immediate).
    - C(lazy) means B(deploy on demand).
    type: str
    choices: [ immediate, lazy ]
  resolution_immediacy:
    description:
    - Determines when the policies should be resolved and available.
    - Defaults to C(lazy) when unset during creation.
    type: str
    choices: [ immediate, lazy, pre-provision ]
  micro_seg_vlan_type:
    description:
    - Virtual LAN type for microsegmentation. This attribute can only be used with VMM domain association.
    type: str
    choices: [ vlan ]
  micro_seg_vlan:
    description:
    - Virtual LAN for microsegmentation. This attribute can only be used with VMM domain association.
    type: int
  port_encap_vlan_type:
    description:
    - Virtual LAN type for port encap. This attribute can only be used with VMM domain association.
    type: str
    choices: [ vlan ]
  port_encap_vlan:
    description:
    - Virtual LAN type for port encap. This attribute can only be used with VMM domain association.
    type: int
  vlan_encap_mode:
    description:
    - Which VLAN enacap mode to use. This attribute can only be used with VMM domain association.
    type: str
    choices: [ static, dynamic ]
  allow_micro_segmentation:
    description:
    - Specifies microsegmentation is enabled or not. This attribute can only be used with VMM domain association.
    type: bool
  switch_type:
    description:
    - Which switch type to use with this domain association. This attribute can only be used with VMM domain association.
    type: str
  switching_mode:
    description:
    - Which switching mode to use with this domain association. This attribute can only be used with VMM domain association.
    type: str
  enhanced_lagpolicy_name:
    description:
    - EPG enhanced lagpolicy name. This attribute can only be used with VMM domain association.
    type: str
  enhanced_lagpolicy_dn:
    description:
    - Distinguished name of EPG lagpolicy. This attribute can only be used with VMM domain association.
    type: str
  delimiter:
    description:
    - Which delimiter to use with this domain association. This attribute can only be used with VMM domain association.
    type: str
    choices: [ '+', '|', '~', '!', '@', '^', '=' ]
  binding_type:
    description:
    - Which binding_type to use with this domain association. This attribute can only be used with VMM domain association.
    type: str
    default: none
    choices: [ static, dynamic, none, ephemeral ]
  num_ports:
    description:
    - Number of ports for the binding type. This attribute can only be used with VMM domain association.
    type: int
  port_allocation:
    description:
    - Port allocation for the binding type. This attribute can only be used with VMM domain association and binding type in static.
    - Required when O(binding_type=static).
    type: str
    choices: [ elastic, fixed ]
  netflow_pref:
    description:
    - The netflow preference state of the domain association. This attribute can only be used with VMM domain association.
    type: str
    default: disabled
    choices: [ enabled, disabled ]
  allow_promiscuous:
    description:
    - The allow promiscuous state of the domain association. This attribute can only be used with VMM domain association.
    type: str
    default: reject
    choices: [ accept, reject ]
  forged_transmits:
    description:
    - The forged transmits state of the domain association. This attribute can only be used with VMM domain association.
    type: str
    default: reject
    choices: [ accept, reject ]
  mac_changes:
    description:
    - The mac changes state of the domain association. This attribute can only be used with VMM domain association.
    type: str
    default: reject
    choices: [ accept, reject ]
  custom_epg_name:
    description:
    - Which custom_epg_name to use with this domain association. This attribute can only be used with VMM domain association.
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
- module: cisco.mso.mso_schema_site_anp_epg
- module: cisco.mso.mso_schema_template_anp_epg
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Add a new domain to a site EPG
  cisco.mso.mso_schema_site_anp_epg_domain:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    anp: ANP1
    epg: EPG1
    domain_association_type: vmmDomain
    domain_profile: 'VMware-VMM'
    deployment_immediacy: lazy
    resolution_immediacy: pre-provision
    state: present

- name: Add a new domain to a site EPG with all possible attributes set
  cisco.mso.mso_schema_site_anp_epg_domain:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    anp: ANP1
    epg: EPG1
    domain_association_type: vmmDomain
    domain_profile: 'VMware-VMM'
    deployment_immediacy: immediate
    resolution_immediacy: immediate
    micro_seg_vlan_type: vlan
    micro_seg_vlan: 100
    port_encap_vlan_type: vlan
    port_encap_vlan: 100
    vlan_encap_mode: static
    allow_micro_segmentation: true
    switch_type: default
    switching_mode: native
    enhanced_lagpolicy_name: ansible_lag_name
    enhanced_lagpolicy_dn: ansible_lag_dn
    delimiter: '|'
    binding_type: static
    num_ports: 2
    port_allocation: elastic
    netflow_pref: enabled
    allow_promiscuous: accept
    forged_transmits: accept
    mac_changes: accept
    custom_epg_name: ansible_custom_epg
    state: present

- name: Query a domain associated with a specific site EPG
  cisco.mso.mso_schema_site_anp_epg_domain:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    anp: ANP1
    epg: EPG1
    domain_association_type: vmmDomain
    domain_profile: 'VMware-VMM'
    state: query
  register: query_result

- name: Query all domains associated with a site EPG
  cisco.mso.mso_schema_site_anp_epg_domain:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    anp: ANP1
    epg: EPG1
    state: query
  register: query_result

- name: Remove a domain from a site EPG
  cisco.mso.mso_schema_site_anp_epg_domain:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    anp: ANP1
    epg: EPG1
    domain_association_type: vmmDomain
    domain_profile: 'VMware-VMM'
    deployment_immediacy: lazy
    resolution_immediacy: pre-provision
    state: absent
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
        anp=dict(type="str", required=True),
        epg=dict(type="str", required=True),
        domain_association_type=dict(type="str", choices=["vmmDomain", "l3ExtDomain", "l2ExtDomain", "physicalDomain", "fibreChannelDomain"]),
        domain_profile=dict(type="str"),
        deployment_immediacy=dict(type="str", choices=["immediate", "lazy"]),
        resolution_immediacy=dict(type="str", choices=["immediate", "lazy", "pre-provision"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        micro_seg_vlan_type=dict(type="str", choices=["vlan"]),
        micro_seg_vlan=dict(type="int"),
        port_encap_vlan_type=dict(type="str", choices=["vlan"]),
        port_encap_vlan=dict(type="int"),
        vlan_encap_mode=dict(type="str", choices=["static", "dynamic"]),
        allow_micro_segmentation=dict(type="bool"),
        switch_type=dict(type="str"),
        switching_mode=dict(type="str"),
        enhanced_lagpolicy_name=dict(type="str"),
        enhanced_lagpolicy_dn=dict(type="str"),
        binding_type=dict(type="str", default="none", choices=["dynamic", "ephemeral", "none", "static"]),
        port_allocation=dict(type="str", choices=["elastic", "fixed"]),
        num_ports=dict(type="int"),
        netflow_pref=dict(type="str", default="disabled", choices=["enabled", "disabled"]),
        allow_promiscuous=dict(type="str", default="reject", choices=["accept", "reject"]),
        forged_transmits=dict(type="str", default="reject", choices=["accept", "reject"]),
        mac_changes=dict(type="str", default="reject", choices=["accept", "reject"]),
        delimiter=dict(type="str", choices=["+", "|", "~", "!", "@", "^", "="]),
        custom_epg_name=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["domain_association_type", "domain_profile", "deployment_immediacy", "resolution_immediacy"]],
            ["state", "present", ["domain_association_type", "domain_profile", "deployment_immediacy", "resolution_immediacy"]],
            ["binding_type", "static", ["port_allocation"]],
        ],
        required_together=[
            ("micro_seg_vlan_type", "micro_seg_vlan"),
            ("port_encap_vlan_type", "port_encap_vlan"),
            ("enhanced_lagpolicy_name", "enhanced_lagpolicy_dn"),
        ],
    )

    schema = module.params.get("schema")
    site = module.params.get("site")
    template = module.params.get("template").replace(" ", "")
    anp = module.params.get("anp")
    epg = module.params.get("epg")
    domain_association_type = module.params.get("domain_association_type")
    domain_profile = module.params.get("domain_profile")
    deployment_immediacy = module.params.get("deployment_immediacy")
    resolution_immediacy = module.params.get("resolution_immediacy")
    state = module.params.get("state")
    micro_seg_vlan_type = module.params.get("micro_seg_vlan_type")
    micro_seg_vlan = module.params.get("micro_seg_vlan")
    port_encap_vlan_type = module.params.get("port_encap_vlan_type")
    port_encap_vlan = module.params.get("port_encap_vlan")
    vlan_encap_mode = module.params.get("vlan_encap_mode")
    allow_micro_segmentation = module.params.get("allow_micro_segmentation")
    switch_type = module.params.get("switch_type")
    switching_mode = module.params.get("switching_mode")
    enhanced_lagpolicy_name = module.params.get("enhanced_lagpolicy_name")
    enhanced_lagpolicy_dn = module.params.get("enhanced_lagpolicy_dn")
    binding_type = module.params.get("binding_type")
    port_allocation = module.params.get("port_allocation")
    num_ports = module.params.get("num_ports")
    netflow_pref = module.params.get("netflow_pref")
    allow_promiscuous = module.params.get("allow_promiscuous")
    forged_transmits = module.params.get("forged_transmits")
    mac_changes = module.params.get("mac_changes")
    delimiter = module.params.get("delimiter")
    custom_epg_name = module.params.get("custom_epg_name")

    mso = MSOModule(module)

    # Get schema objects
    schema_id, schema_path, schema_obj = mso.query_schema(schema)

    # Get template
    templates = [t.get("name") for t in schema_obj.get("templates")]
    if template not in templates:
        mso.fail_json(msg="Provided template '{0}' does not exist. Existing templates: {1}".format(template, ", ".join(templates)))
    template_idx = templates.index(template)

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

    payload = dict()
    ops = []
    op_path = ""
    domain_path = None

    # Get ANP
    anp_ref = mso.anp_ref(schema_id=schema_id, template=template, anp=anp)
    anps = [a.get("anpRef") for a in schema_obj["sites"][site_idx]["anps"]]
    anps_in_temp = [a.get("name") for a in schema_obj["templates"][template_idx]["anps"]]
    if anp not in anps_in_temp:
        mso.fail_json(msg="Provided anp '{0}' does not exist. Existing anps: {1}".format(anp, ", ".join(anps)))
    else:
        # Update anp index at template level
        template_anp_idx = anps_in_temp.index(anp)

    # If anp not at site level but exists at template level
    if anp_ref not in anps:
        op_path = "/sites/{0}/anps/-".format(site_template)
        payload.update(
            anpRef=dict(
                schemaId=schema_id,
                templateName=template,
                anpName=anp,
            ),
        )

    else:
        # Update anp index at site level
        anp_idx = anps.index(anp_ref)

    # Get EPG
    epg_ref = mso.epg_ref(schema_id=schema_id, template=template, anp=anp, epg=epg)

    # If anp exists at site level
    if "anpRef" not in payload:
        epgs = [e.get("epgRef") for e in schema_obj["sites"][site_idx]["anps"][anp_idx]["epgs"]]

    # If anp already at site level AND if epg not at site level (or) anp not at site level?
    if ("anpRef" not in payload and epg_ref not in epgs) or "anpRef" in payload:
        epgs_in_temp = [e.get("name") for e in schema_obj["templates"][template_idx]["anps"][template_anp_idx]["epgs"]]

        # If EPG not at template level - Fail
        if epg not in epgs_in_temp:
            mso.fail_json(msg="Provided EPG '{0}' does not exist. Existing EPGs: {1} epgref {2}".format(epg, ", ".join(epgs_in_temp), epg_ref))

        # EPG at template level but not at site level. Create payload at site level for EPG
        else:
            new_epg = dict(
                epgRef=dict(
                    schemaId=schema_id,
                    templateName=template,
                    anpName=anp,
                    epgName=epg,
                )
            )

            # If anp not in payload then, anp already exists at site level. New payload will only have new EPG payload
            if "anpRef" not in payload:
                op_path = "/sites/{0}/anps/{1}/epgs/-".format(site_template, anp)
                payload = new_epg
            else:
                # If anp in payload, anp exists at site level. Update payload with EPG payload
                payload["epgs"] = [new_epg]

    # Update index of EPG at site level
    else:
        epg_idx = epgs.index(epg_ref)

    if domain_association_type == "vmmDomain":
        domain_dn = "uni/vmmp-VMware/dom-{0}".format(domain_profile)
    elif domain_association_type == "l3ExtDomain":
        domain_dn = "uni/l3dom-{0}".format(domain_profile)
    elif domain_association_type == "l2ExtDomain":
        domain_dn = "uni/l2dom-{0}".format(domain_profile)
    elif domain_association_type == "physicalDomain":
        domain_dn = "uni/phys-{0}".format(domain_profile)
    elif domain_association_type == "fibreChannelDomain":
        domain_dn = "uni/fc-{0}".format(domain_profile)
    else:
        domain_dn = ""

    # Get Domains
    # If anp at site level and epg is at site level
    if "anpRef" not in payload and "epgRef" not in payload:
        domains = [dom.get("dn") for dom in schema_obj["sites"][site_idx]["anps"][anp_idx]["epgs"][epg_idx]["domainAssociations"]]
        if domain_dn in domains:
            domain_idx = domains.index(domain_dn)
            domain_path = "/sites/{0}/anps/{1}/epgs/{2}/domainAssociations/{3}".format(site_template, anp, epg, domain_idx)
            mso.existing = schema_obj["sites"][site_idx]["anps"][anp_idx]["epgs"][epg_idx]["domainAssociations"][domain_idx]

    if state == "query":
        if domain_association_type is None or domain_profile is None:
            mso.existing = schema_obj.get("sites")[site_idx]["anps"][anp_idx]["epgs"][epg_idx]["domainAssociations"]
        elif not mso.existing:
            mso.fail_json(
                msg="Domain association '{domain_association_type}/{domain_profile}' not found".format(
                    domain_association_type=domain_association_type, domain_profile=domain_profile
                )
            )
        mso.exit_json()

    domains_path = "/sites/{0}/anps/{1}/epgs/{2}/domainAssociations".format(site_template, anp, epg)
    ops = []
    new_domain = dict(
        dn=domain_dn,
        domainType=domain_association_type,
        deploymentImmediacy=deployment_immediacy,  # keeping for backworths compatibility
        deployImmediacy=deployment_immediacy,  # rename of deploymentImmediacy
        resolutionImmediacy=resolution_immediacy,
    )

    if domain_association_type == "vmmDomain":
        vmmDomainProperties = {}
        if micro_seg_vlan_type and micro_seg_vlan:
            vmmDomainProperties["microSegVlan"] = dict(vlanType=micro_seg_vlan_type, vlan=micro_seg_vlan)

        if port_encap_vlan_type and port_encap_vlan:
            vmmDomainProperties["portEncapVlan"] = dict(vlanType=port_encap_vlan_type, vlan=port_encap_vlan)

        if vlan_encap_mode:
            vmmDomainProperties["vlanEncapMode"] = vlan_encap_mode

        if allow_micro_segmentation is not None:
            vmmDomainProperties["allowMicroSegmentation"] = allow_micro_segmentation

        if switch_type:
            vmmDomainProperties["switchType"] = switch_type

        if switching_mode:
            vmmDomainProperties["switchingMode"] = switching_mode

        if enhanced_lagpolicy_name and enhanced_lagpolicy_dn:
            vmmDomainProperties["epgLagPol"] = dict(enhancedLagPol=dict(name=enhanced_lagpolicy_name, dn=enhanced_lagpolicy_dn))

        if delimiter:
            vmmDomainProperties["delimiter"] = delimiter

        if binding_type:
            vmmDomainProperties["bindingType"] = binding_type
            vmmDomainProperties["numPorts"] = num_ports

        if port_allocation:
            vmmDomainProperties["portAllocation"] = port_allocation

        if netflow_pref:
            vmmDomainProperties["netflowPref"] = netflow_pref

        if allow_promiscuous:
            vmmDomainProperties["allowPromiscuous"] = allow_promiscuous

        if forged_transmits:
            vmmDomainProperties["forgedTransmits"] = forged_transmits

        if mac_changes:
            vmmDomainProperties["macChanges"] = mac_changes

        if custom_epg_name:
            vmmDomainProperties["customEpgName"] = custom_epg_name

        if vmmDomainProperties:
            new_domain["vmmDomainProperties"] = vmmDomainProperties
            new_domain.update(vmmDomainProperties)

    # If payload is empty, anp and EPG already exist at site level
    if not payload:
        op_path = domains_path + "/-"
        payload = new_domain

    # If payload exists
    else:
        # If anp already exists at site level...(AND payload != epg as well?)
        if "anpRef" not in payload:
            payload["domainAssociations"] = [new_domain]
        else:
            payload["epgs"][0]["domainAssociations"] = [new_domain]

    mso.previous = mso.existing
    if state == "absent":
        if mso.existing and domain_path:
            mso.sent = mso.existing = {}
            ops.append(dict(op="remove", path=domain_path))
    elif state == "present":
        mso.sanitize(payload, collate=True)

        if mso.existing and domain_path:
            ops.append(dict(op="replace", path=domain_path, value=mso.sent))
        else:
            ops.append(dict(op="add", path=op_path, value=mso.sent))

        mso.existing = new_domain

    if not module.check_mode:
        mso.request(schema_path, method="PATCH", data=ops)

    mso.exit_json()


if __name__ == "__main__":
    main()
