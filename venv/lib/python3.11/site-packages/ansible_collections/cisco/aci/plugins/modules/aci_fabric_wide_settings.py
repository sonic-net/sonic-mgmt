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
module: aci_fabric_wide_settings
short_description: Manage Fabric Wide Settings (infra:SetPol)
description:
- Manage Fabric Wide Settings on Cisco ACI fabrics.
options:
  disable_remote_ep_learning:
    description:
    - Whether to disable remote endpoint learning in VRFs containing external bridged/routed domains.
    - The APIC defaults to C(false) when unset during creation.
    type: bool
  enforce_subnet_check:
    description:
    - Whether to disable IP address learning on the outside of subnets configured in a VRF, for all VRFs.
    - The APIC defaults to C(false) when unset during creation.
    type: bool
  enforce_epg_vlan_validation:
    description:
    - Whether to perform a validation check that prevents overlapping VLAN pools from being associated to an EPG.
    - The APIC defaults to C(false) when unset during creation.
    type: bool
  enforce_domain_validation:
    description:
    - Whether to perform a validation check if a static path is added but no domain is associated to an EPG.
    - Asking for domain validation is a one time operation. Once enabled, it cannot be disabled.
    - The APIC defaults to C(false) when unset during creation.
    type: bool
  spine_opflex_client_auth:
    description:
    - Whether to enforce Opflex client certificate authentication on spine switches for GOLF and Linux.
    - The APIC defaults to C(true) when unset during creation.
    type: bool
  leaf_opflex_client_auth:
    description:
    - Whether to enforce Opflex client certificate authentication on leaf switches for GOLF and Linux.
    - The APIC defaults to C(true) when unset during creation.
    type: bool
  spine_ssl_opflex:
    description:
    - Whether to enable SSL Opflex transport for spine switches.
    - The APIC defaults to C(true) when unset during creation.
    type: bool
  leaf_ssl_opflex:
    description:
    - Whether to enable SSL Opflex transport for leaf switches.
    - The APIC defaults to C(true) when unset during creation.
    type: bool
  opflex_ssl_versions:
    description:
    - Which versions of TLS to enable for Opflex.
    - When setting any of the TLS versions, you must explicitly set the state for all of them.
    type: list
    elements: str
    choices: [ tls_v1.0, tls_v1.1, tls_v1.2 ]
  reallocate_gipo:
    description:
    - Whether to reallocate some non-stretched BD gipos to make room for stretched BDs.
    - Asking for gipo reallocation is a one time operation. Once enabled, it cannot be disabled.
    - The APIC defaults to C(false) when unset during creation.
    type: bool
  restrict_infra_vlan_traffic:
    description:
    - Whether to restrict infra VLAN traffic to only specified network paths. These enabled network paths are defined by infra security entry policies.
    - The APIC defaults to C(false) when unset during creation.
    type: bool
  state:
    description:
    - Use C(present) for updating configuration.
    - Use C(query) for showing current configuration.
    type: str
    choices: [ present, query ]
    default: present
extends_documentation_fragment:
- cisco.aci.aci
- cisco.aci.annotation
- cisco.aci.owner

seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(infra:SetPol).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
- Akini Ross (@akinross)
"""

EXAMPLES = r"""
- name: Update Fabric Wide Settings
  cisco.aci.aci_fabric_wide_settings:
    host: apic
    username: admin
    password: SomeSecretPassword
    disable_remote_ep_learning: true
    enforce_epg_vlan_validation: true
    state: present
  delegate_to: localhost

- name: Update Opflex SSL versions
  cisco.aci.aci_fabric_wide_settings:
    host: apic
    username: admin
    password: SomeSecretPassword
    opflex_ssl_versions: [tls_v1.2]
    state: present
  delegate_to: localhost

- name: Query Fabric Wide Settings
  cisco.aci.aci_fabric_wide_settings:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result
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
from ansible_collections.cisco.aci.plugins.module_utils.constants import OPFLEX_TLS_MAPPING


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        disable_remote_ep_learning=dict(type="bool"),
        enforce_subnet_check=dict(type="bool"),
        enforce_epg_vlan_validation=dict(type="bool"),
        enforce_domain_validation=dict(type="bool"),
        spine_opflex_client_auth=dict(type="bool"),
        leaf_opflex_client_auth=dict(type="bool"),
        spine_ssl_opflex=dict(type="bool"),
        leaf_ssl_opflex=dict(type="bool"),
        opflex_ssl_versions=dict(type="list", choices=list(OPFLEX_TLS_MAPPING.keys()), elements="str"),
        reallocate_gipo=dict(type="bool"),
        restrict_infra_vlan_traffic=dict(type="bool"),
        state=dict(type="str", default="present", choices=["present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    aci = ACIModule(module)

    disable_remote_ep_learning = aci.boolean(module.params.get("disable_remote_ep_learning"))
    enforce_subnet_check = aci.boolean(module.params.get("enforce_subnet_check"))
    enforce_epg_vlan_validation = aci.boolean(module.params.get("enforce_epg_vlan_validation"))
    enforce_domain_validation = aci.boolean(module.params.get("enforce_domain_validation"))
    spine_opflex_client_auth = aci.boolean(module.params.get("spine_opflex_client_auth"))
    leaf_opflex_client_auth = aci.boolean(module.params.get("leaf_opflex_client_auth"))
    spine_ssl_opflex = aci.boolean(module.params.get("spine_ssl_opflex"))
    leaf_ssl_opflex = aci.boolean(module.params.get("leaf_ssl_opflex"))
    opflex_ssl_versions = module.params.get("opflex_ssl_versions")
    reallocate_gipo = aci.boolean(module.params.get("reallocate_gipo"))
    restrict_infra_vlan_traffic = aci.boolean(module.params.get("restrict_infra_vlan_traffic"))
    state = module.params.get("state")

    aci.construct_url(
        root_class=dict(
            aci_class="infraSetPol",
            aci_rn="infra/settings",
        ),
    )

    aci.get_existing()

    if state == "present":
        class_config = dict(
            unicastXrEpLearnDisable=disable_remote_ep_learning,
            enforceSubnetCheck=enforce_subnet_check,
            validateOverlappingVlans=enforce_epg_vlan_validation,
            domainValidation=enforce_domain_validation,
            opflexpAuthenticateClients=spine_opflex_client_auth,
            leafOpflexpAuthenticateClients=leaf_opflex_client_auth,
            opflexpUseSsl=spine_ssl_opflex,
            leafOpflexpUseSsl=leaf_ssl_opflex,
            reallocateGipo=reallocate_gipo,
            restrictInfraVLANTraffic=restrict_infra_vlan_traffic,
        )
        if opflex_ssl_versions is not None:
            class_config["opflexpSslProtocols"] = ",".join([OPFLEX_TLS_MAPPING.get(tls) for tls in sorted(opflex_ssl_versions)])

        aci.payload(
            aci_class="infraSetPol",
            class_config=class_config,
        )

        aci.get_diff(aci_class="infraSetPol")

        aci.post_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
