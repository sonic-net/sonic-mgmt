#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Shreyas Srish (@shrsr) <ssrish@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: ndo_ipsla_monitoring_policy
short_description: Manage IPSLA Monitoring Policies on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage IPSLA Monitoring Policies on Cisco Nexus Dashboard Orchestrator (NDO).
- This module is only supported on ND v3.1 (NDO v4.3) and later.
author:
- Shreyas Srish (@shrsr)
options:
  template:
    description:
    - The name of the template.
    - The template must be a tenant template.
    type: str
    required: true
  ipsla_monitoring_policy:
    description:
    - The name of the IPSLA Monitoring Policy.
    type: str
    aliases: [ name ]
  description:
    description:
    - The description of the IPSLA Monitoring Policy.
    type: str
  ipsla_monitoring_policy_uuid:
    description:
    - The UUID of the IPSLA Monitoring Policy.
    - This parameter is required when the O(ipsla_monitoring_policy) attribute needs to be updated.
    type: str
    aliases: [ uuid ]
  sla_type:
    description:
    - The type of SLA.
    - The default value is C(icmp).
    type: str
    choices: [ http, tcp, icmp, l2ping ]
  destination_port:
    description:
    - The port used for SLA.
    - This is only applicable when O(sla_type=tcp) or O(sla_type=http).
    - The value defaults to 80 when O(sla_type=http).
    - The value must be in the range 1 - 65535 when O(sla_type=tcp).
    type: int
  http_version:
    description:
    - The HTTP version used for SLA.
    - This is only applicable when O(sla_type=http).
    - The default value is C(HTTP10).
    type: str
    choices: [ HTTP10, HTTP11 ]
  http_uri:
    description:
    - The URI used for HTTP SLA.
    - This is only applicable when O(sla_type=http).
    - The default value is '/'.
    type: str
  sla_frequency:
    description:
    - The frequency of SLA monitoring in seconds.
    - The value must be in the range 1 - 300.
    - The default value is 60 seconds.
    type: int
  detect_multiplier:
    description:
    - The detection multiplier for SLA.
    - The value must be in the range 1 - 100.
    - The default value is 3.
    type: int
  request_data_size:
    description:
    - The size of the request data in bytes.
    - The value must be in the range 0 - 17513.
    - The default value is 28 bytes.
    type: int
  type_of_service:
    description:
    - The IPv4 Type of Service.
    - The value must be in the range 0 - 255.
    - The default value is 0.
    type: int
  operation_timeout:
    description:
    - The operation_timeout for SLA in milliseconds.
    - The default value is 900 milliseconds.
    type: int
  threshold:
    description:
    - The threshold for SLA in milliseconds.
    - The default value is 900 milliseconds.
    type: int
  ipv6_traffic_class:
    description:
    - The IPv6 Traffic Class.
    - The value must be in the range 0 - 255.
    - The default value is 0.
    type: int
  state:
    description:
    - Use C(absent) for removing.
    - Use C(query) for listing an object or multiple objects.
    - Use C(present) for creating or updating.
    type: str
    choices: [ absent, query, present ]
    default: query
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Create a new IPSLA monitoring policy
  cisco.mso.ndo_ipsla_monitoring_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    ipsla_monitoring_policy: ansible_test_ipsla_monitoring_policy
    sla_type: http
    http_version: HTTP11
    http_uri: /test
    sla_frequency: 120
    detect_multiplier: 5
    request_data_size: 64
    type_of_service: 16
    operation_timeout: 1000
    threshold: 1000
    ipv6_traffic_class: 32
    state: present

- name: Query an IPSLA monitoring policy with name
  cisco.mso.ndo_ipsla_monitoring_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    ipsla_monitoring_policy: ansible_test_ipsla_monitoring_policy
    state: query
  register: query_one

- name: Query all IPSLA monitoring policies in the template
  cisco.mso.ndo_ipsla_monitoring_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    state: query
  register: query_all

- name: Delete an IPSLA monitoring policy
  cisco.mso.ndo_ipsla_monitoring_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    ipsla_monitoring_policy: ansible_test_ipsla_monitoring_policy
    state: absent

- name: Query an IPSLA monitoring policy with UUID
  cisco.mso.ndo_ipsla_monitoring_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    ipsla_monitoring_policy_uuid: "{{ query_one.current.uuid }}"
    state: query
  register: query_one_uuid

- name: Delete an IPSLA monitoring policy with UUID
  cisco.mso.ndo_ipsla_monitoring_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    ipsla_monitoring_policy_uuid: "{{ query_one.current.uuid }}"
    state: absent
"""

RETURN = r"""
"""

import copy
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import (
    MSOModule,
    mso_argument_spec,
)
from ansible_collections.cisco.mso.plugins.module_utils.template import (
    MSOTemplate,
    KVPair,
)
from ansible_collections.cisco.mso.plugins.module_utils.utils import append_update_ops_data


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        template=dict(type="str", required=True),
        ipsla_monitoring_policy=dict(type="str", aliases=["name"]),
        description=dict(type="str"),
        ipsla_monitoring_policy_uuid=dict(type="str", aliases=["uuid"]),
        sla_type=dict(type="str", choices=["http", "tcp", "icmp", "l2ping"]),
        destination_port=dict(type="int"),
        http_version=dict(type="str", choices=["HTTP10", "HTTP11"]),
        http_uri=dict(type="str"),
        sla_frequency=dict(type="int"),
        detect_multiplier=dict(type="int"),
        request_data_size=dict(type="int"),
        type_of_service=dict(type="int"),
        operation_timeout=dict(type="int"),
        threshold=dict(type="int"),
        ipv6_traffic_class=dict(type="int"),
        state=dict(type="str", default="query", choices=["absent", "query", "present"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["ipsla_monitoring_policy", "ipsla_monitoring_policy_uuid"], True],
            ["state", "present", ["ipsla_monitoring_policy", "ipsla_monitoring_policy_uuid"], True],
        ],
    )

    mso = MSOModule(module)

    template = module.params.get("template")
    ipsla_monitoring_policy = module.params.get("ipsla_monitoring_policy")
    description = module.params.get("description")
    ipsla_monitoring_policy_uuid = module.params.get("ipsla_monitoring_policy_uuid")
    sla_type = module.params.get("sla_type")
    destination_port = module.params.get("destination_port")
    http_version = module.params.get("http_version")
    http_uri = module.params.get("http_uri")
    sla_frequency = module.params.get("sla_frequency")
    detect_multiplier = module.params.get("detect_multiplier")
    request_data_size = module.params.get("request_data_size")
    type_of_service = module.params.get("type_of_service")
    operation_timeout = module.params.get("operation_timeout")
    threshold = module.params.get("threshold")
    ipv6_traffic_class = module.params.get("ipv6_traffic_class")
    state = module.params.get("state")

    if sla_frequency is not None and sla_frequency not in range(1, 301):
        mso.fail_json(msg="Invalid value provided for sla_frequency: {0}; it must be in the range 1 - 300".format(sla_frequency))

    if detect_multiplier is not None and detect_multiplier not in range(1, 101):
        mso.fail_json(msg="Invalid value provided for detect_multiplier: {0}; it must be in the range 1 - 100".format(detect_multiplier))

    if request_data_size is not None and request_data_size not in range(0, 17514):
        mso.fail_json(msg="Invalid value provided for request_data_size: {0}; it must be in the range 0 - 17513".format(request_data_size))

    if type_of_service is not None and type_of_service not in range(0, 256):
        mso.fail_json(msg="Invalid value provided for type_of_service: {0}; it must be in the range 0 - 255".format(type_of_service))

    if operation_timeout is not None and sla_frequency is not None and operation_timeout > (sla_frequency * 1000):
        mso.fail_json(
            msg="Invalid value provided for operation_timeout: {0}; must be less than or equal to: {1}".format(operation_timeout, (sla_frequency * 1000))
        )

    if threshold is not None and operation_timeout is not None and threshold > operation_timeout:
        mso.fail_json(
            msg="Invalid value provided for threshold: {0}; it must be less than or equal to the operation_timeout: {1}".format(threshold, operation_timeout)
        )

    if ipv6_traffic_class is not None and ipv6_traffic_class not in range(0, 256):
        mso.fail_json(msg="Invalid value provided for ipv6_traffic_class: {0}; it must be in the range 0 - 255".format(ipv6_traffic_class))

    if sla_type == "http":
        destination_port = 80

    if sla_type != "http":
        if http_version or http_uri:
            mso.fail_json(msg="http_version and http_uri can only be used when sla_type is 'http'")

    ops = []
    match = None

    mso_template = MSOTemplate(mso, "tenant", template)
    mso_template.validate_template("tenantPolicy")
    object_description = "IPSLA Monitoring Policy"

    path = "/tenantPolicyTemplate/template/ipslaMonitoringPolicies"
    match = mso_template.get_ipsla_monitoring_policy(ipsla_monitoring_policy_uuid, ipsla_monitoring_policy)
    if isinstance(match, list):  # Query all policies
        mso.existing = mso.previous = match
    elif match is not None:  # Query a specific policy
        mso.existing = mso.previous = copy.deepcopy(match.details)

    if state == "present":
        mso_values = dict(
            name=ipsla_monitoring_policy,
            description=description,
            slaType=sla_type,
            slaPort=destination_port,
            httpVersion=http_version,
            httpUri=http_uri,
            slaFrequency=sla_frequency,
            slaDetectMultiplier=detect_multiplier,
            reqDataSize=request_data_size,
            ipv4ToS=type_of_service,
            timeout=operation_timeout,
            threshold=threshold,
            ipv6TrfClass=ipv6_traffic_class,
        )
        if match:
            update_path = "{0}/{1}".format(path, match.index)
            append_update_ops_data(ops, match.details, update_path, mso_values)
            mso.sanitize(match.details, collate=True)

        else:
            mso.sanitize(mso_values)
            ops.append(dict(op="add", path="{0}/-".format(path), value=mso.sent))

    elif state == "absent":
        if match:
            ops.append(dict(op="remove", path="{0}/{1}".format(path, match.index)))

    if not module.check_mode and ops:
        response = mso.request(mso_template.template_path, method="PATCH", data=ops)
        ipsla_policies = response.get("tenantPolicyTemplate", {}).get("template", {}).get("ipslaMonitoringPolicies", [])
        match = mso_template.get_object_by_key_value_pairs(
            object_description,
            ipsla_policies,
            [KVPair("uuid", ipsla_monitoring_policy_uuid) if ipsla_monitoring_policy_uuid else KVPair("name", ipsla_monitoring_policy)],
        )
        if match:
            mso.existing = match.details
        else:
            mso.existing = {}
    elif module.check_mode and state != "query":
        mso.existing = mso.proposed if state == "present" else {}

    mso.exit_json()


if __name__ == "__main__":
    main()
