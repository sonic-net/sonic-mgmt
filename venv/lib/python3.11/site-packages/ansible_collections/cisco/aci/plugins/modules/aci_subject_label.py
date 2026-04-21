#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Mark Ciecior (@markciecior)
# Copyright: (c) 2024, Akini Ross <akinross@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_subject_label
short_description: Manage Subject Labels (vz:ConsSubjLbl and vz:ProvSubjLbl)
description:
- Manage Subject Labels on Cisco ACI fabrics.
options:
  tenant:
    description:
    - The name of the Tenant.
    type: str
    aliases: [ tenant_name ]
  l2out:
    description:
    - The name of the L2Out.
    type: str
    aliases: [ l2out_name ]
  l3out:
    description:
    - The name of the L3Out.
    type: str
    aliases: [ l3out_name ]
  external_epg:
    description:
    - The name of the External End Point Group.
    type: str
    aliases: [ extepg, extepg_name, external_epg_name ]
  contract:
    description:
    - The name of the Contract.
    type: str
    aliases: [ contract_name ]
  subject:
    description:
    - The name of the Subject.
    type: str
    aliases: [ subject_name ]
  ap:
    description:
    - The name of the Application Profile.
    type: str
    aliases: [ app_profile, app_profile_name, application_profile, application_profile_name]
  epg:
    description:
    - The name of the End Point Group.
    type: str
    aliases: [ epg_name ]
  esg:
    description:
    - The name of the Endpoint Security Group.
    type: str
    aliases: [ esg_name ]
  subject_label:
    description:
    - The name of the Subject Label.
    type: str
    aliases: [ subject_label_name, name, label ]
  subject_label_type:
    description:
    - Determines the type of the Subject Label.
    type: str
    required: true
    choices: [ consumer, provider ]
    aliases: [ type ]
  complement:
    description:
    - Whether complement is enabled on the Subject Label.
    - The APIC defaults to C(false) when unset during creation.
    type: bool
  tag:
    description:
    - The color of a policy label of the Subject Label.
    - The APIC defaults to C(yellow-green) when unset during creation.
    type: str
    choices:
    - alice_blue
    - antique_white
    - aqua
    - aquamarine
    - azure
    - beige
    - bisque
    - black
    - blanched_almond
    - blue
    - blue_violet
    - brown
    - burlywood
    - cadet_blue
    - chartreuse
    - chocolate
    - coral
    - cornflower_blue
    - cornsilk
    - crimson
    - cyan
    - dark_blue
    - dark_cyan
    - dark_goldenrod
    - dark_gray
    - dark_green
    - dark_khaki
    - dark_magenta
    - dark_olive_green
    - dark_orange
    - dark_orchid
    - dark_red
    - dark_salmon
    - dark_sea_green
    - dark_slate_blue
    - dark_slate_gray
    - dark_turquoise
    - dark_violet
    - deep_pink
    - deep_sky_blue
    - dim_gray
    - dodger_blue
    - fire_brick
    - floral_white
    - forest_green
    - fuchsia
    - gainsboro
    - ghost_white
    - gold
    - goldenrod
    - gray
    - green
    - green_yellow
    - honeydew
    - hot_pink
    - indian_red
    - indigo
    - ivory
    - khaki
    - lavender
    - lavender_blush
    - lawn_green
    - lemon_chiffon
    - light_blue
    - light_coral
    - light_cyan
    - light_goldenrod_yellow
    - light_gray
    - light_green
    - light_pink
    - light_salmon
    - light_sea_green
    - light_sky_blue
    - light_slate_gray
    - light_steel_blue
    - light_yellow
    - lime
    - lime_green
    - linen
    - magenta
    - maroon
    - medium_aquamarine
    - medium_blue
    - medium_orchid
    - medium_purple
    - medium_sea_green
    - medium_slate_blue
    - medium_spring_green
    - medium_turquoise
    - medium_violet_red
    - midnight_blue
    - mint_cream
    - misty_rose
    - moccasin
    - navajo_white
    - navy
    - old_lace
    - olive
    - olive_drab
    - orange
    - orange_red
    - orchid
    - pale_goldenrod
    - pale_green
    - pale_turquoise
    - pale_violet_red
    - papaya_whip
    - peachpuff
    - peru
    - pink
    - plum
    - powder_blue
    - purple
    - red
    - rosy_brown
    - royal_blue
    - saddle_brown
    - salmon
    - sandy_brown
    - sea_green
    - seashell
    - sienna
    - silver
    - sky_blue
    - slate_blue
    - slate_gray
    - snow
    - spring_green
    - steel_blue
    - tan
    - teal
    - thistle
    - tomato
    - turquoise
    - violet
    - wheat
    - white
    - white_smoke
    - yellow
    - yellow_green
  description:
    description:
    - The description for the Subject Label.
    type: str
    aliases: [ descr ]
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

seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(vz:ConsSubjLbl) and (vz:ProvSubjLbl).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Mark Ciecior (@markciecior)
- Akini Ross (@akinross)
"""

EXAMPLES = r"""
- name: Add a Subject Label on a Contract Subject
  cisco.aci.aci_subject_label:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    contract: web
    subject: web_subject
    subject_label: web_subject_label
    subject_type: consumer
    state: present
  delegate_to: localhost

- name: Add a Subject Label on a L2Out External EPG
  cisco.aci.aci_subject_label:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    l2out: l2out_name
    external_epg: external_epg_name
    subject_label: l2out_subject_label
    subject_type: consumer
    state: present
  delegate_to: localhost

- name: Add a Subject Label on a L3Out External EPG
  cisco.aci.aci_subject_label:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    l3out: l3out_name
    external_epg: external_epg_name
    subject_label: l3out_subject_label
    subject_type: consumer
    state: present
  delegate_to: localhost

- name: Add a Subject Label on a L3Out External EPG Contract
  cisco.aci.aci_subject_label:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    l3out: l3out_name
    external_epg: external_epg_name
    contract: web
    subject_label: l3out_subject_label
    subject_type: consumer
    state: present
  delegate_to: localhost

- name: Add a Subject Label on a ESG
  cisco.aci.aci_subject_label:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    ap: app_profile_name
    esg: esg_name
    subject_label: esg_subject_label
    subject_type: consumer
    state: present
  delegate_to: localhost

- name: Add a Subject Label on a EPG
  cisco.aci.aci_subject_label:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    ap: app_profile_name
    epg: epg_name
    subject_label: epg_subject_label
    subject_type: consumer
    state: present
  delegate_to: localhost

- name: Add a Subject Label on a EPG Contract
  cisco.aci.aci_subject_label:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    ap: app_profile_name
    epg: epg_name
    contract: web
    subject_label: epg_subject_label
    subject_type: consumer
    state: present
  delegate_to: localhost

- name: Query a Subject Label on a Contract Subject
  cisco.aci.aci_subject_label:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    contract: web
    subject: web_subject
    subject_label: web_subject_label
    subject_type: consumer
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all Subject Labels
  cisco.aci.aci_subject_label:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

- name: Remove a Subject Label on a Contract Subject
  cisco.aci.aci_subject_label:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    contract: web
    subject: web_subject
    subject_label: web_subject_label
    subject_type: consumer
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
from ansible_collections.cisco.aci.plugins.module_utils.constants import ACI_CLASS_MAPPING, SUBJ_LABEL_MAPPING, SUBJ_LABEL_RN, POLICY_LABEL_COLORS


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        tenant=dict(type="str", aliases=["tenant_name"]),
        l2out=dict(type="str", aliases=["l2out_name"]),
        l3out=dict(type="str", aliases=["l3out_name"]),
        external_epg=dict(type="str", aliases=["extepg", "extepg_name", "external_epg_name"]),
        contract=dict(type="str", aliases=["contract_name"]),
        subject=dict(type="str", aliases=["subject_name"]),
        ap=dict(type="str", aliases=["app_profile", "app_profile_name", "application_profile", "application_profile_name"]),
        epg=dict(type="str", aliases=["epg_name"]),
        esg=dict(type="str", aliases=["esg_name"]),
        complement=dict(type="bool"),
        description=dict(type="str", aliases=["descr"]),
        subject_label=dict(type="str", aliases=["subject_label_name", "name", "label"]),
        subject_label_type=dict(type="str", choices=["consumer", "provider"], aliases=["type"], required=True),
        tag=dict(type="str", choices=POLICY_LABEL_COLORS),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        name_alias=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "present", ["tenant", "subject_label"]],
            ["state", "present", ["l2out", "l3out", "epg", "esg", "subject"], True],
            ["state", "absent", ["tenant", "subject_label"]],
            ["state", "absent", ["l2out", "l3out", "epg", "esg", "subject"], True],
        ],
        mutually_exclusive=[
            ["l2out", "l3out", "epg", "esg", "subject"],
            ["esg", "contract"],
            ["l2out", "contract"],
        ],
        required_by={
            "subject": ["contract"],
            "l2out": ["external_epg"],
            "l3out": ["external_epg"],
            "epg": ["ap"],
            "esg": ["ap"],
        },
    )

    aci = ACIModule(module)

    tenant = module.params.get("tenant")
    l2out = module.params.get("l2out")
    l3out = module.params.get("l3out")
    external_epg = module.params.get("external_epg")
    contract = module.params.get("contract")
    subject_label_type = module.params.get("subject_label_type")
    subject = module.params.get("subject")
    ap = module.params.get("ap")
    epg = module.params.get("epg")
    esg = module.params.get("esg")
    complement = aci.boolean(module.params.get("complement"))
    description = module.params.get("description")
    subject_label = module.params.get("subject_label")
    tag = module.params.get("tag")
    state = module.params.get("state")
    name_alias = module.params.get("name_alias")

    aci_class = SUBJ_LABEL_MAPPING.get(subject_label_type)
    aci_rn = SUBJ_LABEL_RN.get(subject_label_type) + subject_label if subject_label else None

    if contract:
        contract_rn = ACI_CLASS_MAPPING.get(subject_label_type).get("rn") + contract
        contract_class = ACI_CLASS_MAPPING.get(subject_label_type).get("class")

    root_class = dict(
        aci_class="fvTenant",
        aci_rn="tn-{0}".format(tenant),
        module_object=tenant,
        target_filter={"name": tenant},
    )
    subclass_1 = None
    subclass_2 = None
    subclass_3 = None
    subclass_4 = None
    if esg:
        subclass_1 = dict(
            aci_class="fvAp",
            aci_rn="ap-{0}".format(ap),
            module_object=ap,
            target_filter={"name": ap},
        )
        subclass_2 = dict(
            aci_class="fvESg",
            aci_rn="esg-{0}".format(esg),
            module_object=esg,
            target_filter={"name": esg},
        )
        subclass_3 = dict(
            aci_class=aci_class,
            aci_rn=aci_rn,
            module_object=subject_label,
            target_filter={"name": subject_label},
        )
    elif l2out:
        subclass_1 = dict(
            aci_class="l2extOut",
            aci_rn="l2out-{0}".format(l2out),
            module_object=l2out,
            target_filter={"name": l2out},
        )
        subclass_2 = dict(
            aci_class="l2extInstP",
            aci_rn="instP-{0}".format(external_epg),
            module_object=external_epg,
            target_filter={"name": external_epg},
        )
        subclass_3 = dict(
            aci_class=aci_class,
            aci_rn=aci_rn,
            module_object=subject_label,
            target_filter={"name": subject_label},
        )
    elif epg:
        subclass_1 = dict(
            aci_class="fvAp",
            aci_rn="ap-{0}".format(ap),
            module_object=ap,
            target_filter={"name": ap},
        )
        subclass_2 = dict(
            aci_class="fvAEPg",
            aci_rn="epg-{0}".format(epg),
            module_object=epg,
            target_filter={"name": epg},
        )
        if contract:
            subclass_3 = dict(
                aci_class=contract_class,
                aci_rn=contract_rn,
                module_object=contract,
                target_filter={"name": contract},
            )
            subclass_4 = dict(
                aci_class=aci_class,
                aci_rn=aci_rn,
                module_object=subject_label,
                target_filter={"name": subject_label},
            )
        else:
            subclass_3 = dict(
                aci_class=aci_class,
                aci_rn=aci_rn,
                module_object=subject_label,
                target_filter={"name": subject_label},
            )
    elif l3out:
        subclass_1 = subclass_1 = dict(
            aci_class="l3extOut",
            aci_rn="out-{0}".format(l3out),
            module_object=l3out,
            target_filter={"name": l3out},
        )
        subclass_2 = dict(
            aci_class="l3extInstP",
            aci_rn="instP-{0}".format(external_epg),
            module_object=external_epg,
            target_filter={"name": external_epg},
        )
        if contract:
            subclass_3 = dict(
                aci_class=contract_class,
                aci_rn=contract_rn,
                module_object=contract,
                target_filter={"name": contract},
            )
            subclass_4 = dict(
                aci_class=aci_class,
                aci_rn=aci_rn,
                module_object=subject_label,
                target_filter={"name": subject_label},
            )
        else:
            subclass_3 = dict(
                aci_class=aci_class,
                aci_rn=aci_rn,
                module_object=subject_label,
                target_filter={"name": subject_label},
            )
    elif subject:
        subclass_1 = dict(
            aci_class="vzBrCP",
            aci_rn="brc-{0}".format(contract),
            module_object=contract,
            target_filter={"name": contract},
        )
        subclass_2 = dict(
            aci_class="vzSubj",
            aci_rn="subj-{0}".format(subject),
            module_object=subject,
            target_filter={"name": subject},
        )
        subclass_3 = dict(
            aci_class=aci_class,
            aci_rn=aci_rn,
            module_object=subject_label,
            target_filter={"name": subject_label},
        )
    else:  # Query scenario without any filters forcing class query on the subject_label_class
        root_class = dict(
            aci_class=aci_class,
            aci_rn=aci_rn,
            module_object=subject_label,
            target_filter={"name": subject_label},
        )

    aci.construct_url(
        root_class=root_class,
        subclass_1=subclass_1,
        subclass_2=subclass_2,
        subclass_3=subclass_3,
        subclass_4=subclass_4,
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class=aci_class,
            class_config=dict(
                name=subject_label,
                descr=description,
                nameAlias=name_alias,
                isComplement=complement,
                tag=tag.replace("_", "-") if tag else None,
            ),
        )

        aci.get_diff(aci_class=aci_class)

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
