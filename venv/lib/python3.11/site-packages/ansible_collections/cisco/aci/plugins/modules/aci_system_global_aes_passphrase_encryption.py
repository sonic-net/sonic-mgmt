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
module: aci_system_global_aes_passphrase_encryption
short_description: Manage Global AES Passphrase Encryption Settings (pki:ExportEncryptionKey)
description:
- Manage Global AES Passphrase Encryption Settings on Cisco ACI fabrics.
options:
  passphrase:
    description:
    - The AES passphrase to use for configuration export encryption.
    - This cannot be modified once in place on the APIC. To modify an existing passphrase, you must delete it by sending a request with state C(absent).
    - The value of the passphrase will not be shown in the results of a C(query).
    type: str
  enable:
    description:
    - Whether to enable strong encryption.
    - The APIC defaults to C(false) when unset during creation.
    - Note that this will be set back to False when deleting an existing passphrase.
    type: bool
  state:
    description:
    - Use C(present) to create a passphrase or to change the enable setting.
    - Use C(absent) to delete the existing passphrase.
    - Use C(query) for showing current configuration.
    type: str
    choices: [ absent, present, query ]
    default: present
extends_documentation_fragment:
- cisco.aci.aci
- cisco.aci.annotation
- cisco.aci.owner

seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(pki:ExportEncryptionKey).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
- Akini Ross (@akinross)
"""

EXAMPLES = r"""
- name: Enable encryption with a passphrase
  cisco.aci.aci_system_global_aes_passphrase_encryption:
    host: apic
    username: admin
    password: SomeSecretPassword
    passphrase: ansible_passphrase
    enable: 'yes'
    state: present
  delegate_to: localhost

- name: Query passphrase settings
  cisco.aci.aci_system_global_aes_passphrase_encryption:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

- name: Clear encryption key
  cisco.aci.aci_system_global_aes_passphrase_encryption:
    host: apic
    username: admin
    password: SomeSecretPassword
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


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        passphrase=dict(type="str", no_log=True),
        enable=dict(type="bool"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    aci = ACIModule(module)

    passphrase = module.params.get("passphrase")
    enable = aci.boolean(module.params.get("enable"))
    state = module.params.get("state")

    aci.construct_url(
        root_class=dict(
            aci_class="pkiExportEncryptionKey",
            aci_rn="exportcryptkey",
        ),
    )

    aci.get_existing()

    if state in ["present", "absent"]:
        class_config = dict(passphrase=passphrase, strongEncryptionEnabled=enable) if state == "present" else dict(clearEncryptionKey="yes")

        aci.payload(aci_class="pkiExportEncryptionKey", class_config=class_config)

        aci.get_diff(aci_class="pkiExportEncryptionKey")

        aci.post_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
