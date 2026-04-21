#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Tim Cragg (@timcragg)
# Copyright: (c) 2025, Shreyas Srish (@shrsr)
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: aci_l4l7_policy_based_redirect
version_added: "2.12.0"
short_description: Manage L4-L7 Policy Based Redirection Policies (vns:SvcRedirectPol)
description:
- Manage Layer 4 to Layer 7 (L4-L7) Policy Based Redirection
options:
  tenant:
    description:
    - The name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
  policy_name:
    description:
    - The name of the Policy Based Redirection Policy.
    type: str
    aliases: [ policy ]
  description:
    description:
    - The description of the Policy Based Redirection Policy.
    type: str
  destination_type:
    description:
    - The destination type.
    - The APIC defaults to C(l3) when unset during creation.
    type: str
    choices: [ l1, l2, l3 ]
    aliases: [ dest_type ]
  hash_algorithm:
    description:
    - The hashing algorithm.
    - The APIC defaults to C(ip_and_protocol) when unset during creation.
    type: str
    choices: [ source_ip, destination_ip, ip_and_protocol ]
  threshold_enable:
    description:
    - Whether to enable the threshold for the policy.
    - The APIC defaults to C(false) when unset during creation.
    type: bool
  max_threshold:
    description:
    - The maximum percent when threshold is enabled.
    - The APIC defaults to C(0) when unset during creation.
    - Permitted values are in the range of [0, 100].
    type: int
  min_threshold:
    description:
    - The minimum percent when threshold is enabled.
    - The APIC defaults to C(0) when unset during creation.
    - Permitted values are in the range of [0, 100].
    type: int
  threshold_down_action:
    description:
    - The action to take when threshold is breached.
    - The APIC defaults to C(permit) when unset during creation.
    type: str
    choices: [ deny, permit ]
  resilient_hash:
    description:
    - Whether to enable resilient hashing.
    - The APIC defaults to C(false) when unset during creation.
    type: bool
  pod_aware:
    description:
    - Whether to enable Pod ID aware redirection.
    - The APIC defaults to C(false) when unset during creation.
    type: bool
  anycast_enabled:
    description:
    - Whether to enable anycast services.
    - The APIC defaults to C(false) when unset during creation.
    - Only available when I(destination_type=l3)
    type: bool
  ip_sla_monitor_policy:
    description:
    - The name of the IP SLA Monitoring Policy to bind to the L4-L7 Redirect Policy.
    - To remove an existing binding to an IP SLA Monitoring Policy, submit a request with I(state=present) and I(ip_sla_monitor_policy="") value.
    type: str
    aliases: [ monitor_policy, sla, sla_policy ]
  rewrite_source_mac:
    description:
    - Whether to rewrite the source MAC address of forwarded traffic.
    - The APIC defaults to C(false) when unset during creation.
    type: bool
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
extends_documentation_fragment:
- cisco.aci.aci
- cisco.aci.annotation
- cisco.aci.owner
notes:
- The I(tenant) must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant) module can be used for this.
seealso:
- module: cisco.aci.aci_tenant
- name: APIC Management Information Model reference
  description: More information about the internal APIC class, B(vns:SvcRedirectPol)
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
- Shreyas Srish (@shrsr)
"""

EXAMPLES = r"""
- name: Add a new Policy Based Redirect
  cisco.aci.aci_l4l7_policy_based_redirect:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    policy_name: my_pbr_policy
    destination_type: l3
    hash_algorithm: destination_ip
    resilient_hash: true
    state: present
  delegate_to: localhost

- name: Query a Policy Based Redirect
  cisco.aci.aci_l4l7_policy_based_redirect:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    policy_name: my_pbr_policy
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all Policy Based Redirects
  cisco.aci.aci_l4l7_policy_based_redirect:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

- name: Delete a Policy Based Redirect
  cisco.aci.aci_l4l7_policy_based_redirect:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    policy_name: my_pbr_policy
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
from ansible_collections.cisco.aci.plugins.module_utils.constants import L4L7_HASH_ALGORITHMS_MAPPING


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        tenant=dict(type="str", aliases=["tenant_name"]),
        policy_name=dict(type="str", aliases=["policy"]),
        description=dict(type="str"),
        destination_type=dict(type="str", aliases=["dest_type"], choices=["l1", "l2", "l3"]),
        hash_algorithm=dict(type="str", choices=list(L4L7_HASH_ALGORITHMS_MAPPING)),
        threshold_enable=dict(type="bool"),
        max_threshold=dict(type="int"),
        min_threshold=dict(type="int"),
        threshold_down_action=dict(type="str", choices=["permit", "deny"]),
        resilient_hash=dict(type="bool"),
        pod_aware=dict(type="bool"),
        anycast_enabled=dict(type="bool"),
        ip_sla_monitor_policy=dict(type="str", aliases=["monitor_policy", "sla", "sla_policy"]),
        rewrite_source_mac=dict(type="bool"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["tenant", "policy_name"]],
            ["state", "present", ["tenant", "policy_name"]],
        ],
    )
    aci = ACIModule(module)

    tenant = module.params.get("tenant")
    state = module.params.get("state")
    policy_name = module.params.get("policy_name")
    description = module.params.get("description")
    destination_type = module.params.get("destination_type").upper() if module.params.get("destination_type") is not None else None
    hash_algorithm = L4L7_HASH_ALGORITHMS_MAPPING.get(module.params.get("hash_algorithm"))
    threshold_enable = aci.boolean(module.params.get("threshold_enable"))
    max_threshold = module.params.get("max_threshold")
    min_threshold = module.params.get("min_threshold")
    threshold_down_action = module.params.get("threshold_down_action")
    resilient_hash = aci.boolean(module.params.get("resilient_hash"))
    pod_aware = aci.boolean(module.params.get("pod_aware"))
    anycast_enabled = aci.boolean(module.params.get("anycast_enabled"))
    ip_sla_monitor_policy = module.params.get("ip_sla_monitor_policy")
    rewrite_source_mac = aci.boolean(module.params.get("rewrite_source_mac"))

    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter={"name": tenant},
        ),
        subclass_1=dict(
            aci_class="vnsSvcRedirectPol",
            aci_rn="svcCont/svcRedirectPol-{0}".format(policy_name),
            module_object=policy_name,
            target_filter={"name": policy_name},
        ),
        child_classes=["vnsRsIPSLAMonitoringPol"],
    )

    aci.get_existing()

    if state == "present":
        child_configs = []
        if ip_sla_monitor_policy:
            monitor_tdn = "uni/tn-{0}/ipslaMonitoringPol-{1}".format(tenant, ip_sla_monitor_policy)
            child_configs.append({"vnsRsIPSLAMonitoringPol": {"attributes": {"tDn": monitor_tdn}}})
        else:
            monitor_tdn = None
        if isinstance(aci.existing, list) and len(aci.existing) > 0:
            for child in aci.existing[0].get("vnsSvcRedirectPol", {}).get("children", {}):
                if child.get("vnsRsIPSLAMonitoringPol") and child.get("vnsRsIPSLAMonitoringPol").get("attributes").get("tDn") != monitor_tdn:
                    child_configs.append(
                        {
                            "vnsRsIPSLAMonitoringPol": {
                                "attributes": {
                                    "dn": child.get("vnsRsIPSLAMonitoringPol").get("attributes").get("dn"),
                                    "status": "deleted",
                                }
                            }
                        }
                    )
        aci.payload(
            aci_class="vnsSvcRedirectPol",
            class_config=dict(
                name=policy_name,
                descr=description,
                destType=destination_type,
                hashingAlgorithm=hash_algorithm,
                maxThresholdPercent=max_threshold,
                minThresholdPercent=min_threshold,
                programLocalPodOnly=pod_aware,
                resilientHashEnabled=resilient_hash,
                thresholdDownAction=threshold_down_action,
                thresholdEnable=threshold_enable,
                AnycastEnabled=anycast_enabled,
                srcMacRewriteEnabled=rewrite_source_mac,
            ),
            child_configs=child_configs,
        )
        aci.get_diff(aci_class="vnsSvcRedirectPol")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
