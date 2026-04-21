# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)


DOCUMENTATION = """
---
module: hv_storage_component
short_description: Create or update a storage component
description:
  - This module creates or updates a storage component in Hitachi VSP One Object.
version_added: '1.0.0'
author:
  - Hitachi Vantara, LTD. (@hitachi-vantara)
requirements:
  - python >= 3.7
attributes:
  check_mode:
    description: Determines if the module should run in check mode.
    support: none
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
  state:
    description:
      - Set operation to C(activate) for activating storage component
      - Set operation to C(test) for testing storage component connection
      - Set operation to C(present) for creating or updating storage component
    type: str
    choices: ['activate', 'test', 'present']
    required: false
  spec:
    description: Storage component module spec
    type: dict
    required: true
    suboptions:
      id:
        description:
          - The ID of the storage component.
          - If specified, only updates are performed.
        type: str
        required: false
      storage_type:
        description:
          - The type of storage component.
          - Set storage_type to C(HCPS_S3) for HCPS S3 storage component.
          - Set storage_type to C(ARRAY) for VSP SDS Block storage component.
        type: str
        "choices": ['HCPS_S3', 'ARRAY']
        required: false
      storage_custom_metadata:
        description: The metadata assigned to the storage component.
        type: dict
        required: false
      storage_component_config:
        description: The storage component configuration values.
        type: dict
        required: false
        suboptions:
          label:
            description:
              - The name of the storage component.
              - Mandatory when creating a storage component.
            type: str
            required: false
          host:
            description:
              - The URL of the storage component back-end host domain.
              - Mandatory when creating a storage component.
            type: str
            required: false
          storage_class:
            description:
              - The storage class associated with the storage component.
              - Mandatory when creating a storage component.
            type: str
            required: false
          storage_fault_domain:
            description:
              - The fault domain associated with the storage component.
              - Mandatory when creating a storage component.
            type: str
            required: false
          uri_scheme:
            description:
              - The Uniform Resource Identifier (URI) schema used when accessing the resource.
              - Use C(HTTP) for an unsecured connection, or C(HTTPS) for a secure connection.
            type: str
            choices: ['HTTP', 'HTTPS']
            required: false
          port:
            description:
              - The HTTP port of the back-end system.
              - Mandatory when creating a storage component.
            type: str
            required: false
          bucket:
            description:
              - The name of the bucket.
              - The bucket must already exist.
              - Mandatory when creating a storage component.
            type: str
            required: false
          region:
            description: The S3 region. Mandatory when creating a storage component.
            type: str
            required: false
          auth_type:
            description:
              - The AWS Signature Version for authenticating all interactions with Amazon S3.
              - Use C(V2) for an unsecured connection, or C(V4) for a secure connection.
            type: str
            choices: ['V2','V4']
            default: 'V2'
            required: false
          access_key:
            description:
              - The access key of the S3 credentials for access to the bucket.
              - Mandatory when creating a storage component.
            type: str
            required: false
          secret_key:
            description:
              - The secret key of the S3 credentials for access to the bucket.
              - Mandatory when creating a storage component.
            type: str
            required: false
          use_proxy:
            description: If true, then values are required for proxy_host, proxy_port, proxy_user_name, and proxy_password.
            type: bool
            required: false
          proxy_host:
            description: The proxy server host.
            type: str
            required: false
          proxy_port:
            description: The proxy port number.
            type: str
            required: false
          proxy_user_name:
            description: The proxy domain username.
            type: str
            required: false
          proxy_password:
            description: The proxy domain password.
            type: str
            required: false
          proxy_domain:
            description: The proxy domain. This is not supported.
            type: str
            required: false
          management_user:
            description:
              - Required for an VSP One Object S Series node storage component.
              - The administrative user name credential.
              - Do not provide for other storage component types.
            type: str
            required: false
          management_password:
            description:
              - Required for an VSP One Object S Series node storage component.
              - The password credential.
              - Do not provide for other storage component types.
            type: str
            required: false
          management_protocol:
            description:
              - Required for an VSP One Object S Series node storage component.
              - The communication protocol for MAPI requests.
              - Do not provide for other storage component types.
            type: str
            required: false
          management_host:
            description:
              - Required for an VSP One Object S Series node storage component.
              - Type the management system IP address or fully qualified domain name.
              - Do not provide for other storage component types.
            type: str
            required: false
          use_path_style_always:
            description:
              - If true, use path-style syntax to send requests to the back-end system.
              - If false, use virtual-hosted style.
              - If not specified, defaults to true.
            type: bool
            required: false
          activate_now:
            description: Activate storage component immediately.
            type: bool
            required: false
            default: true
          connection_timeout:
            description: Timeout for establishing HTTP connections (milliseconds).
            type: int
            required: false
          socket_timeout:
            description: The timeout value for reading from a connected socket.
            type: int
            required: false
          connection_ttl:
            description: The connection time to live (TTL) for a request.
            type: int
            required: false
          max_connections:
            description: The maximum number of open HTTP connections to a storage component.
            type: int
            required: false
          user_agent_prefix:
            description: The HTTP user agent prefix header, used in requests to a storage component.
            type: str
            required: false
          socket_send_buffer_size_hint:
            description:
              - The size hint, in bytes, for the low-level TCP send buffer.
              - If specified, you must also specify socketRecvBufferSizeHint.
            type: int
            required: false
          socket_recv_buffer_size_hint:
            description:
              - The size hint, in bytes, for the low-level TCP receive buffer.
              - If specified, you must also specify socketSendBufferSizeHint.
            type: int
            required: false
          namespace:
            description: The Kubernetes namespace associated with the storage component.
            type: str
            required: false
          data_persistent_volume_name:
            description: The persistent volume (PV) associated with the storage component.
            type: str
            required: false
          data_claim_capacity:
            description: The amount of storage requested for the storage component.
            type: str
            required: false
          node:
            description: The node on the Kubernetes cluster on which the storage is to be allocated.
            type: str
            required: false
          array_name:
            description: The name of the storage array.
            type: str
            required: false
          array_storage_tier:
            description: The storage tier on the storage array.
            type: str
            required: false
"""

EXAMPLES = """
- name: Activate storage component in Hitachi VSP One Object
  hitachivantara.vspone_object.oneobject_node.hv_storage_component:
    connection_info:
      http_request_timeout: 300
      http_request_retry_times: 3
      http_request_retry_interval_seconds: 5
      cluster_name: "your_cluster_name"
      region: "your_region"
      oneobject_node_username: "your_username"
      oneobject_node_userpass: "your_password"
      oneobject_node_client_id: "vsp-object-external-client"
    state: "activate"
    spec:
      id: 759156789

- name: Create storage component in Hitachi VSP One Object
  hitachivantara.vspone_object.oneobject_node.hv_storage_component:
    connection_info:
      http_request_timeout: 300
      http_request_retry_times: 3
      http_request_retry_interval_seconds: 5
      cluster_name: "your_cluster_name"
      region: "your_region"
      oneobject_node_username: "your_username"
      oneobject_node_userpass: "your_password"
      oneobject_node_client_id: "vsp-object-external-client"
      state: "present"
      spec:
        storage_type: "HCPS_S3"
        storage_component_config:
          label: "component-test6"
          host: "172.25.57.10"
          storage_class: "A1-CLASS-3_123"
          storage_fault_domain: "humphrey-storage-test"
          uri_scheme: "HTTP"
          port: "80"
          bucket: "ansiblecreate6"
          region: "us-west-2b"
          auth_type: "V2"
          access_key: "dxfchgvjh"
          secret_key: "thsfgndzbfvzdc"
          use_proxy: false
          proxy_host: ~
          proxy_port: ~
          proxy_user_name: ~
          proxy_password: ~
          management_user: "johndoenag"
          management_password: "Passw0rd!"
          management_protocol: "HTTPS"
          management_host: "172.25.57.10:9090/mapi"
          use_path_style_always: false
          activate_now: false

- name: Update storage component in Hitachi VSP One Object
  hitachivantara.vspone_object.oneobject_node.hv_storage_component:
    connection_info:
      http_request_timeout: 300
      http_request_retry_times: 3
      http_request_retry_interval_seconds: 5
      cluster_name: "your_cluster_name"
      region: "your_region"
      oneobject_node_username: "your_username"
      oneobject_node_userpass: "your_password"
      oneobject_node_client_id: "vsp-object-external-client"
      state: "present"
      spec:
        storage_type: "HCPS_S3"
        storage_component_config:
          label: "component-test6"
          host: "172.25.57.10"
          storage_class: "A1-CLASS-3_123"
          storage_fault_domain: "humphrey-storage-test"
          uri_scheme: "HTTP"
          port: "80"
          bucket: "ansiblecreate6"
          region: "us-west-2b"
          auth_type: "V2"
          access_key: "dxfchgvjh"
          secret_key: "thsfgndzbfvzdc"
          use_proxy: false
          proxy_host: ~
          proxy_port: ~
          proxy_user_name: ~
          proxy_password: ~
          management_user: "johndoenag"
          management_password: "Passw0rd!"
          management_protocol: "HTTPS"
          management_host: "172.25.57.10:9090/mapi"
          use_path_style_always: false
          activate_now: false

- name: Test storage component access in Hitachi VSP One Object
  hitachivantara.vspone_object.oneobject_node.hv_storage_component:
    connection_info:
      http_request_timeout: 300
      http_request_retry_times: 3
      http_request_retry_interval_seconds: 5
      cluster_name: "your_cluster_name"
      region: "your_region"
      oneobject_node_username: "your_username"
      oneobject_node_userpass: "your_password"
      oneobject_node_client_id: "vsp-object-external-client"
    state: "test"
    spec:
      id: 759156789
"""

RETURN = r"""
storage_component:
  description: Storage component and its attributes.
  returned: success
  type: dict
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
          sample: "test_bucket"
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
"""


from ansible.module_utils.basic import AnsibleModule

from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.ansible_argument_spec_oo import (
    OOArgumentSpec,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.params_oo import (
    OOConnectionInfoParam, Tokens, ActivateStorageComponentParam, CreateStorageComponentParam, StorageComponentTestParam
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.common_msg_catalog import (
    CommonMsgCatalog as CMCA,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.gateway_oo import (
    OOGateway,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.storage_components import (
    StorageComponentResource,
)

from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.storage_components_msg_catalog import (
    StorageComponentMsgCatalog as SCMA,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


def main():
    logger = Log()

    fields = OOArgumentSpec.storage_component()

    module = AnsibleModule(argument_spec=fields)
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
    json_spec["state"] = module.params.get("state", "")
    logger.writeDebug("json_spec: {}".format(json_spec))

    operation_map = {
        "activate": "ACTIVATE",
        "test": "TEST",
        "present": "",
    }

    input_params = None

    json_spec["operation"] = json_spec.pop("state", "")

    if json_spec["operation"] in operation_map:
        json_spec["operation"] = operation_map[json_spec["operation"]]
    else:
        json_spec["operation"] = ""
    json_spec["operation"] = json_spec.get("operation", "")
    if not json_spec["operation"]:
        json_spec["operation"] = ""
    if json_spec["operation"] == "ACTIVATE":
        input_params = ActivateStorageComponentParam(
            conn_info_param, json_spec
        )
    elif json_spec["operation"] == "TEST":
        input_params = StorageComponentTestParam(
            conn_info_param, json_spec
        )
    else:
        input_params = CreateStorageComponentParam(
            conn_info_param, json_spec
        )

    try:
        if input_params:
            input_params.validate()
    except Exception as err:
        module.fail_json(msg=CMCA.ERR_VALIDATION.value.format(err))

    logger.writeDebug(
        "storage_component_param={}".format(input_params)
    )
    raw_message = ""
    isCreateOrUpdate = False
    changed = False
    isTest = False
    try:
        storage_component_res = StorageComponentResource(
            input_params, tokens
        )
        if json_spec["operation"] == "ACTIVATE":
            raw_message_dict = storage_component_res.activate_storage_component()
            changed = raw_message_dict.pop("changed", False)
            raw_message = raw_message_dict.pop("data", "")
        elif json_spec["operation"] == "TEST":
            isTest = True
            logger.writeDebug("Testing storage component connectivity")
            raw_message = storage_component_res.test_access()
            changed = raw_message.pop("changed", False)
        else:
            isCreateOrUpdate = True
    except Exception as err:
        if isTest:
            if "404" in str(err):
                id = json_spec.get("id", "")
                err = "Storage component with id {} is not found".format(id)
            module.fail_json(msg=SCMA.ERR_TEST_STORAGE_COMPONENT.value.format(err))
        module.fail_json(msg=SCMA.ERR_ACTIVATE_STORAGE_COMPONENT.value.format(err))
    if isCreateOrUpdate:
        try:
            storage_component_res = StorageComponentResource(
                input_params, tokens
            )
            if json_spec["operation"] == "":
                json_spec.pop("operation", "")
                storage_component_res.id = json_spec.pop("id", "NA")
                logger.writeDebug("remove invalid fields")
                raw_message = storage_component_res.create_one()
                changed = raw_message.pop("changed", False)
        except Exception as err:
            logger.writeDebug(err)
            module.fail_json(msg=SCMA.ERR_CREATE_STORAGE_COMPONENT.value.format(err))
    registration_message = validate_ansible_product_registration()
    response = {
        "changed": changed,
        "storage_component": raw_message,
    }

    if registration_message:
        response["user_consent_required"] = registration_message

    module.exit_json(**response)
    # module.exit_json(changed=True, data=raw_message, user_consent_required=registration_message)


if __name__ == '__main__':
    main()
