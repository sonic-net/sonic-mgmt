#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Sabari Jaganathan (@sajagana) <sajagana@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: ndo_schema_template_contract_service_chain
version_added: "2.11.0"
short_description: Manage the Schema Template Contract Service Chaining workflow on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage the Schema Template Contract Service Chaining workflow on Cisco Nexus Dashboard Orchestrator (NDO).
- This module is only supported on ND v3.1 (NDO v4.2.3) and later.
- This module is the recommended approach for Service Chaining over the previous solution using M(cisco.mso.mso_schema_template_contract_service_graph).
- This module is incompatible with M(cisco.mso.mso_schema_template_contract_service_graph).
author:
- Sabari Jaganathan (@sajagana)
options:
  schema:
    description:
    - The name of the schema.
    - This parameter is mutually exclusive with O(schema_id).
    - This parameter or O(schema_id) is required when O(template) is set.
    type: str
  schema_id:
    description:
    - The ID of the schema.
    - This parameter is mutually exclusive with O(schema).
    - This parameter or O(schema) is required when O(template) is set.
    type: str
  template:
    description:
    - The name of the template.
    - This parameter is mutually exclusive with O(template_id).
    type: str
  template_id:
    description:
    - The ID of the template.
    - This parameter is mutually exclusive with O(template).
    type: str
  contract:
    description:
    - The name of the contract.
    - This parameter is mutually exclusive with O(contract_uuid).
    type: str
  contract_uuid:
    description:
    - The UUID of the contract.
    - This parameter is mutually exclusive with O(contract).
    type: str
  node_filter:
    description:
    - The Filter After First Device option of the contract service chain.
    - This enables traffic filtering to be dynamically applied after the first device in the chain has processed the traffic.
    - Defaults to O(node_filter=allow_all) when unset during creation.
    type: str
    choices: [ allow_all, filters_from_contract ]
    aliases: [ filter_after_first_device ]
  service_nodes:
    description:
    - The list of service nodes for the contract service chain.
    - This parameter is required for creating the contract service chain.
    - Providing a new list of O(service_nodes) will completely replace an existing one from the contract service chain.
    type: list
    elements: dict
    suboptions:
      device_type:
        description:
        - The type of the service device.
        type: str
        choices: [ firewall, load_balancer, other ]
        required: true
        aliases: [ type ]
      uuid:
        description:
        - The UUID of the service device.
        - This parameter is mutually exclusive with O(service_nodes.device).
        - This parameter or O(service_nodes.device) is required.
        type: str
        aliases: [ device_uuid ]
      provider_interface_name:
        description:
        - The name of the service device interface used as the provider interface in the contract service chain.
        type: str
        required: true
        aliases: [ provider_interface, provider ]
      provider_redirect:
        description:
        - The provider redirect option of the contract service chain.
        - Defaults to O(service_nodes.provider_redirect=false) when unset during creation.
        type: bool
      consumer_interface_name:
        description:
        - The name of the service device interface used as the consumer interface in the contract service chain.
        type: str
        required: true
        aliases: [ consumer_interface, consumer ]
      consumer_redirect:
        description:
        - The consumer redirect option of the contract service chain.
        - Defaults to O(service_nodes.consumer_redirect=false) when unset during creation.
        type: bool
      device:
        description:
        - The service device details for the contract service chain.
        - This parameter is mutually exclusive with O(service_nodes.uuid).
        - This parameter or O(service_nodes.uuid) is required.
        type: dict
        suboptions:
          name:
            description:
            - The name of the service device.
            type: str
            required: true
          template:
            description:
            - The template name of the service device.
            - This parameter is mutually exclusive with O(service_nodes.device.template_id).
            - This parameter or O(service_nodes.device.template_id) is required.
            type: str
          template_id:
            description:
            - The template id of the service device.
            - This parameter is mutually exclusive with O(service_nodes.device.template).
            - This parameter or O(service_nodes.device.template) is required.
            type: str
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
seealso:
- module: cisco.mso.mso_schema_template_contract_filter
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Add schema template contract service chain
  cisco.mso.ndo_schema_template_contract_service_chain:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: schema1
    template: template1
    contract: contract1
    node_filter: allow_all
    service_nodes:
      - device_type: load_balancer
        consumer_interface_name: lb_interface1
        provider_interface_name: lb_interface2
        consumer_redirect: true
        provider_redirect: true
        device:
          name: load_balancer_device
          template: service_device_template
    state: present

- name: Update schema template contract service chain with multiple nodes
  cisco.mso.ndo_schema_template_contract_service_chain:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: schema1
    template: template1
    contract: contract1
    node_filter: "filters_from_contract"
    service_nodes:
      - device_type: load_balancer
        consumer_interface_name: lb_interface1
        provider_interface_name: lb_interface2
        consumer_redirect: true
        provider_redirect: true
        device:
          name: load_balancer_device
          template: service_device_template
      - device_type: firewall
        consumer_interface_name: fw_interface1
        provider_interface_name: fw_interface2
        uuid: "{{ service_device.current.uuid }}"
    state: present

- name: Query schema template contract service chain
  cisco.mso.ndo_schema_template_contract_service_chain:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: schema1
    template: template1
    contract: contract1
    state: query
  register: query_service_chain

- name: Delete schema template contract service chain
  cisco.mso.ndo_schema_template_contract_service_chain:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: schema1
    template: template1
    contract: contract1
    state: absent
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec
from ansible_collections.cisco.mso.plugins.module_utils.templates import MSOTemplates
from ansible_collections.cisco.mso.plugins.module_utils.template import MSOTemplate
from ansible_collections.cisco.mso.plugins.module_utils.template import KVPair
from ansible_collections.cisco.mso.plugins.module_utils.utils import snake_to_camel
from ansible_collections.cisco.mso.plugins.module_utils.constants import CONTRACT_SERVICE_CHAIN_NODE_FILTER_MAP
from ansible_collections.cisco.mso.plugins.module_utils.utils import delete_none_values
import copy


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        schema=dict(type="str"),
        schema_id=dict(type="str"),
        template=dict(type="str"),
        template_id=dict(type="str"),
        contract=dict(type="str"),
        contract_uuid=dict(type="str"),
        node_filter=dict(type="str", choices=list(CONTRACT_SERVICE_CHAIN_NODE_FILTER_MAP), aliases=["filter_after_first_device"]),
        service_nodes=dict(
            type="list",
            elements="dict",
            options=dict(
                device_type=dict(type="str", choices=["firewall", "load_balancer", "other"], required=True, aliases=["type"]),
                uuid=dict(type="str", aliases=["device_uuid"]),
                device=dict(
                    type="dict",
                    options=dict(
                        name=dict(type="str", required=True),
                        template=dict(type="str"),
                        template_id=dict(type="str"),
                    ),
                    mutually_exclusive=[["template", "template_id"]],
                    required_one_of=[["template", "template_id"]],
                ),
                provider_interface_name=dict(type="str", required=True, aliases=["provider_interface", "provider"]),
                provider_redirect=dict(type="bool"),
                consumer_interface_name=dict(type="str", required=True, aliases=["consumer_interface", "consumer"]),
                consumer_redirect=dict(type="bool"),
            ),
            mutually_exclusive=[["uuid", "device"]],
            required_one_of=[["uuid", "device"]],
        ),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "present", ["service_nodes"]],
        ],
        mutually_exclusive=[["schema", "schema_id"], ["template", "template_id"], ["contract", "contract_uuid"]],
        required_one_of=[["contract", "contract_uuid"], ["template", "template_id"]],
    )

    schema = module.params.get("schema")
    schema_id = module.params.get("schema_id")
    template = module.params.get("template")
    template_id = module.params.get("template_id")
    contract = module.params.get("contract")
    contract_uuid = module.params.get("contract_uuid")
    node_filter = CONTRACT_SERVICE_CHAIN_NODE_FILTER_MAP.get(module.params.get("node_filter"))
    service_nodes = module.params.get("service_nodes")
    state = module.params.get("state")

    mso = MSOModule(module)

    if not template_id and not (schema or schema_id):
        mso.fail_json(msg="The schema or schema_id is required when the template is set.")

    mso_templates = MSOTemplates(mso)
    mso_template = MSOTemplate(mso, "application", template, template_id, schema_name=schema, schema_id=schema_id)

    template_id = template_id or mso_template.template.get("templateId")
    template = template or mso_template.template.get("appTemplate", {}).get("template", {}).get("name")
    contract_match = mso_template.get_application_template_contract(contract_uuid, contract, fail_module=True)
    service_chain = contract_match.details.get("serviceChaining") if contract_match and contract_match.details.get("serviceChaining") else {}

    reference_collections = {
        "serviceDeviceRef": {
            "name": "deviceName",
            "reference": "deviceRef",
            "type": "serviceDevice",
            "template": "deviceTemplateName",
            "templateId": "deviceTemplateId",
        },
    }

    if service_chain:
        mso.existing = mso.previous = mso_template.update_config_with_template_and_references(
            service_chain, reference_collections, set_template=True, use_cache=True
        )  # Query a specific object

    service_chain_path = "/templates/{0}/contracts/{1}/serviceChaining".format(template, contract_match.details.get("name"))

    ops = []

    if state == "present":
        mso_values = dict(nodeFilter=node_filter)
        service_nodes_config = []
        if service_nodes:
            for index, service_node in enumerate(service_nodes, start=1):
                if not service_node.get("uuid"):
                    service_node_template = mso_templates.get_template(
                        "service_device", service_node.get("device").get("template"), service_node.get("device").get("template_id")
                    )
                    service_devices = service_node_template.template.get("deviceTemplate", {}).get("template", {}).get("devices") or []
                    service_node_match = service_node_template.get_object_by_key_value_pairs(
                        "Service Device Cluster",
                        service_devices,
                        [KVPair("name", service_node.get("device").get("name"))],
                        fail_module=True,
                    )
                    service_node["uuid"] = service_node_match.details.get("uuid")

                service_nodes_config.append(
                    {
                        "index": index,
                        "name": "node-{0}".format(index),
                        "deviceRef": service_node.get("uuid"),
                        "deviceType": snake_to_camel(service_node.get("device_type")),
                        "providerConnector": {
                            "interfaceName": service_node.get("provider_interface_name"),
                            "isRedirect": service_node.get("provider_redirect"),
                        },
                        "consumerConnector": {
                            "interfaceName": service_node.get("consumer_interface_name"),
                            "isRedirect": service_node.get("consumer_redirect"),
                        },
                    }
                )

        mso_values["serviceNodes"] = service_nodes_config
        mso.sanitize(delete_none_values(mso_values))
        ops.append(dict(op="replace" if mso.existing else "add", path=service_chain_path, value=mso.sent))

    elif state == "absent" and mso.existing:
        ops.append(dict(op="remove", path=service_chain_path))

    if not module.check_mode and ops:
        mso.request(mso_template.schema_path, method="PATCH", data=ops)
        mso_template = MSOTemplate(mso, "application", None, template_id)
        contract_match = mso_template.get_application_template_contract(contract_uuid, contract, fail_module=True)
        service_chain = contract_match.details.get("serviceChaining") if contract_match and contract_match.details.get("serviceChaining") else {}

        if service_chain:
            mso.existing = mso_template.update_config_with_template_and_references(
                service_chain, reference_collections, set_template=True, use_cache=True
            )  # When the state is present
        else:
            mso.existing = {}  # When the state is absent

    elif module.check_mode and state != "query":  # When the state is present/absent with check mode
        if state == "present":
            mso.existing = mso_template.update_config_with_template_and_references(
                copy.deepcopy(mso.proposed), reference_collections, set_template=True, use_cache=True
            )
        else:
            mso.existing = {}

    mso.exit_json()


if __name__ == "__main__":
    main()
