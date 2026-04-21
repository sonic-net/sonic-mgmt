#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Christian Kolrep <christian.kolrep@dataport.de>
# Copyright: (c) 2024, Akini Ross <akinross@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_epg
short_description: Manage End Point Groups (EPG) objects (fv:AEPg)
description:
- Manage End Point Groups (EPG) on Cisco ACI fabrics.
options:
  tenant:
    description:
    - Name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
  ap:
    description:
    - Name of an existing application network profile, that will contain the EPGs.
    type: str
    aliases: [ app_profile, app_profile_name ]
  epg:
    description:
    - Name of the end point group.
    type: str
    aliases: [ epg_name, name ]
  bd:
    description:
    - Name of the bridge domain being associated with the EPG.
    type: str
    aliases: [ bd_name, bridge_domain ]
  priority:
    description:
    - The QoS class.
    - The APIC defaults to C(unspecified) when unset during creation.
    type: str
    choices: [ level1, level2, level3, unspecified ]
  intra_epg_isolation:
    description:
    - The Intra EPG Isolation.
    - The APIC defaults to C(unenforced) when unset during creation.
    type: str
    choices: [ enforced, unenforced ]
  description:
    description:
    - Description for the EPG.
    type: str
    aliases: [ descr ]
  fwd_control:
    description:
    - The forwarding control used by the EPG.
    - The APIC defaults to C(none) when unset during creation.
    type: str
    choices: [ none, proxy-arp ]
  preferred_group:
    description:
    - Whether or not the EPG is part of the Preferred Group and can communicate without contracts.
    - This is very convenient for migration scenarios, or when ACI is used for network automation but not for policy.
    - The APIC defaults to C(false) when unset during creation.
    type: bool
  monitoring_policy:
    description:
    - The name of the monitoring policy.
    type: str
  custom_qos_policy:
    description:
    - The name of the custom Quality of Service policy.
    type: str
  useg:
    description:
    - Use C(yes) to create uSeg EPG and C(no) is used to create Application EPG.
    type: str
    choices: [ 'yes', 'no' ]
  match:
    description:
    - The match type of the default Block Statement (fv:Crtrn).
    - The APIC defaults to C(any) when unset during creation.
    type: str
    choices: [ any, all ]
  precedence:
    description:
    - The Block Statement(fv:Crtrn) Precedence to resolve equal matches between micro segmented EPGs.
    - The APIC defaults to C(0) when unset during creation.
    type: int
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

notes:
- The C(tenant) and C(app_profile) used must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant) and M(cisco.aci.aci_ap) modules can be used for this.
seealso:
- module: cisco.aci.aci_tenant
- module: cisco.aci.aci_ap
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(fv:AEPg).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Swetha Chunduri (@schunduri)
- Shreyas Srish (@shrsr)
- Christian Kolrep (@Christian-Kolrep)
- Akini Ross (@akinross)
"""

EXAMPLES = r"""
- name: Add a new EPG
  cisco.aci.aci_epg:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    ap: intranet
    epg: web_epg
    description: Web Intranet EPG
    bd: prod_bd
    monitoring_policy: default
    preferred_group: true
    state: present
  delegate_to: localhost

- name: Add a new uSeg EPG
  cisco.aci.aci_epg:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    ap: intranet
    epg: web_epg
    description: Web Intranet EPG
    bd: prod_bd
    monitoring_policy: default
    preferred_group: true
    useg: 'yes'
    state: present
  delegate_to: localhost

- name: Add a uSeg EPG with block statement match and precedence
  cisco.aci.aci_epg:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    ap: intranet
    epg: web_epg
    description: Web Intranet EPG
    bd: prod_bd
    monitoring_policy: default
    preferred_group: true
    useg: 'yes'
    match: all
    precedence: 1
    state: present
  delegate_to: localhost

- name: Query an EPG
  cisco.aci.aci_epg:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    ap: ticketing
    epg: web_epg
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all EPGs
  cisco.aci.aci_epg:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all EPGs with a Specific Name
  cisco.aci.aci_epg:
    host: apic
    username: admin
    password: SomeSecretPassword
    validate_certs: false
    epg: web_epg
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all EPGs of an App Profile
  cisco.aci.aci_epg:
    host: apic
    username: admin
    password: SomeSecretPassword
    validate_certs: false
    ap: ticketing
    state: query
  delegate_to: localhost
  register: query_result

- name: Remove an EPG
  cisco.aci.aci_epg:
    host: apic
    username: admin
    password: SomeSecretPassword
    validate_certs: false
    tenant: production
    app_profile: intranet
    epg: web_epg
    monitoring_policy: default
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
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(
        epg=dict(type="str", aliases=["epg_name", "name"]),  # Not required for querying all objects
        bd=dict(type="str", aliases=["bd_name", "bridge_domain"]),
        ap=dict(type="str", aliases=["app_profile", "app_profile_name"]),  # Not required for querying all objects
        tenant=dict(type="str", aliases=["tenant_name"]),  # Not required for querying all objects
        description=dict(type="str", aliases=["descr"]),
        priority=dict(type="str", choices=["level1", "level2", "level3", "unspecified"]),
        intra_epg_isolation=dict(choices=["enforced", "unenforced"]),
        fwd_control=dict(type="str", choices=["none", "proxy-arp"]),
        preferred_group=dict(type="bool"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        name_alias=dict(type="str"),
        monitoring_policy=dict(type="str"),
        custom_qos_policy=dict(type="str"),
        useg=dict(type="str", choices=["yes", "no"]),
        match=dict(type="str", choices=["all", "any"]),
        precedence=dict(type="int"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["ap", "epg", "tenant"]],
            ["state", "present", ["ap", "epg", "tenant"]],
        ],
    )

    aci = ACIModule(module)

    epg = module.params.get("epg")
    bd = module.params.get("bd")
    description = module.params.get("description")
    priority = module.params.get("priority")
    intra_epg_isolation = module.params.get("intra_epg_isolation")
    fwd_control = module.params.get("fwd_control")
    preferred_group = aci.boolean(module.params.get("preferred_group"), "include", "exclude")
    state = module.params.get("state")
    tenant = module.params.get("tenant")
    ap = module.params.get("ap")
    name_alias = module.params.get("name_alias")
    monitoring_policy = module.params.get("monitoring_policy")
    custom_qos_policy = module.params.get("custom_qos_policy")
    useg = module.params.get("useg")
    match = module.params.get("match")
    precedence = module.params.get("precedence")

    child_configs = [dict(fvRsBd=dict(attributes=dict(tnFvBDName=bd))), dict(fvRsAEPgMonPol=dict(attributes=dict(tnMonEPGPolName=monitoring_policy)))]

    if custom_qos_policy is not None:
        child_configs.append(dict(fvRsCustQosPol=dict(attributes=dict(tnQosCustomPolName=custom_qos_policy))))

    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter={"name": tenant},
        ),
        subclass_1=dict(
            aci_class="fvAp",
            aci_rn="ap-{0}".format(ap),
            module_object=ap,
            target_filter={"name": ap},
        ),
        subclass_2=dict(
            aci_class="fvAEPg",
            aci_rn="epg-{0}".format(epg),
            module_object=epg,
            target_filter={"name": epg},
        ),
        child_classes=["fvRsBd", "fvRsAEPgMonPol", "fvRsCustQosPol", "fvCrtrn"],
    )

    aci.get_existing()

    if state == "present":
        if useg is not None and aci.existing and aci.existing[0]["fvAEPg"]["attributes"]["isAttrBasedEPg"] != useg:
            module.fail_json(msg="Changing attribute useg on existing EPG is not supported.")
        if useg == "yes":
            child_configs.append(dict(fvCrtrn=dict(attributes=dict(name="default", match=match, prec=precedence))))

        aci.payload(
            aci_class="fvAEPg",
            class_config=dict(
                name=epg,
                descr=description,
                prio=priority,
                pcEnfPref=intra_epg_isolation,
                fwdCtrl=fwd_control,
                prefGrMemb=preferred_group,
                nameAlias=name_alias,
                isAttrBasedEPg=useg,
            ),
            child_configs=child_configs,
        )

        aci.get_diff(aci_class="fvAEPg")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
