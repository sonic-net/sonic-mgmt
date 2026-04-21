#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Tim Cragg (@timcragg) <tcragg@cisco.com>
# Copyright: (c) 2023, Akini Ross (@akinross) <akinross@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_system_banner
short_description: Manages Alias and Banners (aaa:PreLoginBanner)
description:
- Manages Alias and Banners on Cisco ACI fabrics.
options:
  description:
    description:
    - The description of the AAA login banner.
    type: str
  gui_alias:
    description:
    - The system GUI alias.
    type: str
  controller_banner:
    description:
    - The contents of the CLI informational banner to be displayed before user login authentication.
    - The CLI banner is a text based string printed as-is to the console.
    type: str
  switch_banner:
    description:
    - The switch banner message.
    type: str
  application_banner:
    description:
    - The application banner message.
    type: str
  severity:
    description:
    - The application banner severity.
    type: str
    choices: [ critical, info, major, minor, warning ]
  gui_banner:
    description:
    - The contents of the GUI informational banner to be displayed before user login authentication.
    - When I(gui_banner) starts with I(http://) or I(https://) the banner will be of URL type.
    - Note that the URL site owner must allow the site to be placed in an iFrame to display the informational banner.
    type: str
  state:
    description:
    - Use C(present) for updating.
    - Use C(query) for listing an object.
    type: str
    choices: [ present, query ]
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
  description: More information about the internal APIC class B(aaa:PreLoginBanner).
  link: https://developer.cisco.com/docs/apic-mim-ref/

author:
- Tim Cragg (@timcragg)
- Akini Ross (@akinross)
"""

EXAMPLES = r"""
- name: Configure banner
  cisco.aci.aci_system_banner:
    host: apic
    username: admin
    password: SomeSecretPassword
    gui_alias: "Test GUI Alias"
    controller_banner: "Test Controller Banner"
    application_banner: "Test Application Banner"
    severity: critical
    switch_banner: "Test Switch Banner"
    gui_banner: "Test GUI Banner"
    state: present
  delegate_to: localhost

- name: Configure banner with a url
  cisco.aci.aci_system_banner:
    host: apic
    username: admin
    password: SomeSecretPassword
    gui_alias: "Test GUI Alias"
    controller_banner: "Test Controller Banner Message"
    application_banner: "Test Application Banner"
    severity: critical
    switch_banner: "Test Switch Banner Message"
    gui_banner: https://www.cisco.com
    state: present
  delegate_to: localhost

- name: Query banner
  cisco.aci.aci_system_banner:
    host: apic
    username: admin
    password: SomeSecretPassword
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


import re
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec, aci_owner_spec


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        description=dict(type="str"),
        gui_alias=dict(type="str"),
        controller_banner=dict(type="str"),
        switch_banner=dict(type="str"),
        application_banner=dict(type="str"),
        severity=dict(type="str", choices=["critical", "info", "major", "minor", "warning"]),
        gui_banner=dict(type="str"),
        name_alias=dict(type="str"),
        state=dict(type="str", default="present", choices=["present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_by={"severity": "application_banner"},
    )
    aci = ACIModule(module)

    description = module.params.get("description")
    gui_alias = module.params.get("gui_alias")
    controller_banner = module.params.get("controller_banner")
    switch_banner = module.params.get("switch_banner")
    application_banner = module.params.get("application_banner")
    severity = module.params.get("severity")
    gui_banner = module.params.get("gui_banner")
    state = module.params.get("state")
    name_alias = module.params.get("name_alias")

    aci.construct_url(
        root_class=dict(
            aci_class="aaaPreLoginBanner",
            aci_rn="userext/preloginbanner",
        ),
    )
    aci.get_existing()

    if state == "present":
        regex_url = "^https?:\\/\\/(?:www\\.)?[-a-zA-Z0-9@:%._\\+~#=]{1,256}\\.[a-zA-Z0-9()]{1,6}\\b(?:[-a-zA-Z0-9()@:%_\\+.~#?&\\/=]*)$"

        if gui_banner is not None and re.fullmatch(regex_url, gui_banner):
            is_gui_message_text = "no"
        else:
            is_gui_message_text = "yes"

        aci.payload(
            aci_class="aaaPreLoginBanner",
            class_config=dict(
                descr=description,
                bannerMessage=application_banner,
                bannerMessageSeverity=severity,
                guiMessage=gui_banner,
                guiTextMessage=gui_alias,
                isGuiMessageText=is_gui_message_text,
                message=controller_banner,
                showBannerMessage="yes" if application_banner else "no",
                switchMessage=switch_banner,
                nameAlias=name_alias,
            ),
        )

        aci.get_diff(aci_class="aaaPreLoginBanner")

        aci.post_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
