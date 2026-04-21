# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)


DOCUMENTATION = """
---
module: hv_storage_components_facts
short_description: Get storage components from VSP One Object
description:
  - This module queries storage components from Hitachi VSP One Object.
version_added: '1.0.0'
author:
  - Hitachi Vantara, LTD. (@hitachi-vantara)
requirements:
  - python >= 3.7
attributes:
  check_mode:
    description: Determines if the module should run in check mode.
    support: full
options:
  connection_info:
    description: Information required to establish a connection to the system.
    type: dict
    required: true
    suboptions:
      http_request_timeout:
        description: Timeout for HTTP requests.
        type: int
        required: true
      http_request_retry_times:
        description: Number of times to retry an HTTP request.
        type: int
        required: true
      http_request_retry_interval_seconds:
        description: Interval between retries of an HTTP request.
        type: int
        required: true
      cluster_name:
        description: Cluster name of the system.
        type: str
        required: true
      region:
        description: Region of the system.
        type: str
        required: true
      oneobject_node_username:
        description: Username for authentication.
        type: str
        required: true
      oneobject_node_userpass:
        description: Password for authentication.
        type: str
        required: true
      oneobject_node_client_id:
        description: Id for authentication.
        type: str
        required: true
      oneobject_node_client_secret:
        description: Secret for authentication.
        type: str
        required: false
      ssl:
        description: SSL configuration.
        type: dict
        required: false
        suboptions:
          validate_certs:
            description: Whether to validate SSL certificates.
            type: bool
            required: true
          client_cert:
            description: Path to the client certificate file.
            type: str
            required: false
            default: ''
          client_key:
            description: Path to the client key file.
            type: str
            required: false
            default: ''
          ca_path:
            description: Path to the CA certificate file.
            type: str
            required: false
            default: ''
          ssl_version:
            description: SSL version to use.
            type: str
            required: false
            default: ''
          ca_certs:
            description: Path to the CA certificates file.
            type: str
            required: false
            default: ''
          ssl_cipher:
            description: SSL cipher to use.
            type: str
            required: false
            default: ''
          check_hostname:
            description: Whether to check the hostname.
            type: bool
            required: false
            default: false
  spec:
    description: Storage component fact module spec
    type: dict
    required: false
    suboptions:
      query:
        description: Type of query to perform on storage components.
        type: str
        required: false
      page_size:
        description:
          - Number of storage components to retrieve per page when querying.
          - This parameter is ignored if the parameter `query` is provided.
        type: int
        required: false
"""

EXAMPLES = """
- name: Get storage components
  hitachivantara.vspone_object.oneobject_node.hv_storage_components_facts:
    connection_info:
      http_request_timeout: 300
      http_request_retry_times: 3
      http_request_retry_interval_seconds: 5
      cluster_name: "your_cluster_name"
      region: "your_region"
      oneobject_node_username: "your_username"
      oneobject_node_userpass: "your_password"
      oneobject_node_client_id: "vsp-object-external-client"

- name: Get n number of storage components
  hitachivantara.vspone_object.oneobject_node.hv_storage_components_facts:
    connection_info:
      http_request_timeout: 300
      http_request_retry_times: 3
      http_request_retry_interval_seconds: 5
      cluster_name: "your_cluster_name"
      region: "your_region"
      oneobject_node_username: "your_username"
      oneobject_node_userpass: "your_password"
      oneobject_node_client_id: "vsp-object-external-client"
    spec:
      page_size: 2

- name: Get storage components capacity
  hitachivantara.vspone_object.oneobject_node.hv_storage_components_facts:
    connection_info:
      http_request_timeout: 300
      http_request_retry_times: 3
      http_request_retry_interval_seconds: 5
      cluster_name: "your_cluster_name"
      region: "your_region"
      oneobject_node_username: "your_username"
      oneobject_node_userpass: "your_password"
      oneobject_node_client_id: "vsp-object-external-client"
    spec:
      query: "CAPACITY"
"""

EXAMPLES = """
- name: Get storage components module
  hosts: localhost
  gather_facts: false
  vars_files:
    - connection_setting.yml
  vars:
    connection_info:
      http_request_timeout: "{{ http_request_timeout }}"
      http_request_retry_times: "{{ http_request_retry_times }}"
      http_request_retry_interval_seconds: "{{ http_request_retry_interval_seconds }}"
      ssl: "{{ ssl }}"
      cluster_name: "{{ cluster_name }}"
      region: "{{ region }}"
      oneobject_node_username: "{{ oneobject_node_username }}"
      oneobject_node_userpass: "{{ oneobject_node_userpass }}"
      oneobject_node_client_id: "{{ oneobject_node_client_id }}"
      oneobject_node_client_secret: "{{ oneobject_node_client_secret }}"

  tasks:
    - name: Get storage components
      hitachivantara.vspone_object.oneobject_node.hv_storage_components_facts:
        connection_info: "{{ connection_info }}"
      register: output_variable
"""

RETURN = r"""
ansible_facts:
  description: >
    Dictionary containing the discovered properties of the storage components.
  returned: always
  type: dict
  contains:
    storage_components:
      description: List of storage components with their attributes.
      type: list
      elements: dict
      contains:
        id:
          description: The ID of the storage component.
          type: int
          sample: 1473644437
        storage_class_id:
          description: The id of storage class assigned to the storage component in Kubernetes.
          type: int
          sample: -1128696871
        storage_component_config:
          description: The storage component configuration values.
          type: dict
          contains:
            auth_type:
              description: The AWS Signature Version for authenticating all interactions with Amazon S3.
              type: str
              sample: "V2"
            bucket:
              description: The name of the bucket.
              type: str
              sample: "test_bucket  "
            connection_ttl:
              description: The connection time to live (TTL) for a request.
              type: int
              sample: 0
            host:
              description: The URL of the storage component back-end host domain.
              type: str
              sample: "urloripaddressofcomponent"
            label:
              description: The name of the storage component.
              type: str
              sample: "component-test6"
            management_host:
              description: The management system IP address or fully qualified domain name.
              type: str
              sample: "urloripaddressofcomponentmapi"
            management_protocol:
              description: The communication protocol for MAPI requests.
              type: str
              sample: "HTTPS"
            max_connections:
              description: The maximum number of connections for the storage component.
              type: int
              sample: 1024
            port:
              description: The HTTP port of the back-end system.
              type: int
              sample: 80
            region:
              description: The S3 region.
              type: str
              sample: "us-west-2b"
            site_affiliation:
              description: The site affiliation details for the storage component.
              type: dict
              contains:
                id:
                  description: The unique identifier of the site affiliation.
                  type: str
                  sample: "6e8ba3a8-b477-484a-95cf-9d3b29e1699d"
            socket_timeout:
              description: The timeout value for reading from a connected socket.
              type: int
              sample: 31000
            state:
              description: The current state of the storage component.
              type: str
              sample: "UNVERIFIED"
            uri_scheme:
              description: The Uniform Resource Identifier (URI) schema used when accessing the resource.
              type: str
              sample: "HTTP"
            use_path_style_always:
              description: Whether to use path-style addressing for the storage component.
              type: bool
              sample: false
            use_proxy:
              description: Whether to use a proxy for the storage component.
              type: bool
              sample: false
            array_lun:
              description: The LUN on the storage array.
              type: str
              sample: "lun1"
            array_name:
              description: The name of the storage array.
              type: str
              sample: "vsp_array_01"
            array_namespace:
              description: The namespace on the storage array.
              type: str
              sample: "namespace1"
            array_storage_tier:
              description: The storage tier on the storage array.
              type: str
              sample: "nvme-tlc"
        storage_custom_metadata:
          description: Custom metadata for the storage component.
          type: dict
          sample: {}
        storage_fault_domain_id:
          description: The unique identifier of the storage fault domain.
          type: str
          sample: "073cddb1-01f2-45a3-8688-50a1483d9e53"
        storage_type:
          description: The type of the storage component.
          type: str
          sample: "HCPS_S3"
        storage_capacities:
          description: The storage capacities of the storage component.
          type: dict
          contains:
            available_bytes:
              description: The total number of unused bytes on your S3 component.
              type: int
              sample: 100000
            total_bytes:
              description: The total number of bytes on your S3 component.
              type: int
              sample: 10000000000
            used_bytes:
              description: The total number of used bytes on your S3 component.
              type: int
              sample: 9999000000
            warn_threshold:
              description: The percentage of total capacity usage at which point a warning message is generated.
              type: int
              sample: 50
            available_capacity:
              description: Available capacity in human-readable format.
              type: str
              sample: "100.0 GB"
            total_capacity:
              description: Total capacity in human-readable format.
              type: str
              sample: "10.0 TB"
            used_capacity:
              description: Used capacity in human-readable format.
              type: str
              sample: "9.9 TB"
            warn_threshold_capacity:
              description: Warning threshold capacity in human-readable format.
              type: str
              sample: "5.0 TB"
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.ansible_argument_spec_oo import (
    OOArgumentSpec, )
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.params_oo import (
    OOConnectionInfoParam, Tokens, StorageComponentFactsParam)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.gateway_oo import (
    OOGateway, )
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.storage_components import (
    StorageComponentResource, )
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.common_msg_catalog import (
    CommonMsgCatalog as CMCA, )
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration, )


def main():
    logger = Log()

    fields = OOArgumentSpec.storage_component_facts()
    module = AnsibleModule(argument_spec=fields, supports_check_mode=True)
    connection_info = module.params['connection_info']

    gw = OOGateway()

    conn_info_param = OOConnectionInfoParam(
        connection_info["http_request_timeout"],
        connection_info["http_request_retry_times"],
        connection_info["http_request_retry_interval_seconds"],
        connection_info["ssl"],
        connection_info["cluster_name"],
        connection_info["region"],
        connection_info["oneobject_node_username"],
        connection_info["oneobject_node_userpass"],
        connection_info["oneobject_node_client_id"],
        connection_info["oneobject_node_client_secret"])

    bearer_token, xsrf_token, vertx_session = "", "", ""

    try:
        bearer_token, xsrf_token, vertx_session = gw.get_tokens(
            conn_info_param)
    except Exception as err:
        logger.writeDebug(CMCA.AUTH_VALIDATION_ERR.value.format(err))
        module.fail_json(msg=CMCA.AUTH_VALIDATION_ERR.value.format(err))

    tokens = Tokens(bearer_token, xsrf_token, vertx_session)

    json_spec = module.params['spec']

    storage_component_param = StorageComponentFactsParam(
        conn_info_param, json_spec=json_spec
    )
    try:
        if storage_component_param:
            storage_component_param.validate()
    except Exception as err:
        module.fail_json(msg=CMCA.ERR_VALIDATION.value.format(err))

    logger.writeDebug(
        "storage_component_param={}".format(storage_component_param)
    )
    raw_message = ""
    capacity_query = False
    page_token = ""
    try:
        storage_components = StorageComponentResource(
            storage_component_param, tokens
        )
        if json_spec and json_spec.get("query", None) == "CAPACITY":
            capacity_query = True
            raw_message = storage_components.get_capacity()
            logger.writeDebug("storage capacity={}".format(raw_message))
            if "storage_capacities" in raw_message.keys():
                for key, value in raw_message["storage_capacities"].items():
                    value["available_capacity"] = storage_component_param.format_bytes(value["available_bytes"])
                    value["total_capacity"] = storage_component_param.format_bytes(value["total_bytes"])
                    value["used_capacity"] = storage_component_param.format_bytes(value["used_bytes"])
                    value["warn_threshold_capacity"] = storage_component_param.format_bytes(value["warn_threshold"])
                    raw_message["storage_capacities"][key] = value

        elif json_spec and json_spec.get("page_size", None) > 0:
            raw_message = storage_components.query_n()
            page_token = raw_message.get("page_token", None)
            logger.writeDebug("Initial page_token={}".format(page_token))
            raw_message = raw_message.get("storage_components", [])

        else:
            raw_message = storage_components.query_all()
            raw_message = raw_message.get("storage_components", [])
    except Exception as err:
        module.fail_json(msg=CMCA.ERR_CMN_REASON.value.format(err))

    registration_message = validate_ansible_product_registration()

    response = {
        "storage_components": raw_message,
    }
    if page_token != "":
        response["page_token"] = page_token

    if registration_message:
        response["user_consent_required"] = registration_message

    result = {
        "ansible_facts": response,
        "changed": False,
    }
    module.exit_json(**result)

    # module.exit_json(changed=False, data=raw_message)


if __name__ == '__main__':
    main()
