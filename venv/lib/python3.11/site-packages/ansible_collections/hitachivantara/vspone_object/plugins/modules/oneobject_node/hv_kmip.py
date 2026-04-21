# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)


DOCUMENTATION = """
---
module: hv_kmip
short_description: Manage KMIP servers on VSP One Object
description:
  - This module manages KMIP servers on Hitachi VSP One Object Node.
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
      - Set operation to C(present) for adding a new KMIP server
      - Set operation to C(absent) for deleting a KMIP server
      - Set operation to C(promote) for promoting a KMIP server
      - Set operation to C(modify) for modifying an existing KMIP server
    type: str
    choices: ['present', 'absent', 'promote', 'modify']
    required: true
  spec:
    description: Request parameters for managing KMIP servers.
    type: dict
    required: true
    suboptions:
      name:
        description:
          - The user-assigned name of the KMIP server you want to add.
          - Type up to 63 Unicode characters.
          - The server name must be unique.
        type: str
        required: true
      host:
        description: The host name or IP address of the KMIP server.
        type: str
        required: false
      port:
        description: The port number of the KMIP server.
        type: int
        required: false
      is_tls12_enabled:
        description:
          - Whether TLS 1.2 is enabled for the KMIP server.
          - C(true) if TLS v1.2 is enabled, C(false) otherwise.
          - TLS v1.2 support is provided for backward compatibility only.
        type: bool
        default: true
        required: false
      kmip_protocol:
        description: The version of the KMIP protocol assigned to the server.
        type: str
        required: false
        default: "V1_4"
      https_ciphers:
        description:
          - A string of comma-separated cyphers to use for HTTPS connections.
          - The default group supports interoperability with a range of commercial key managers.
        type: str
        required: false
      uuid:
        description: The UUID of the server.
        type: str
        required: false
"""

EXAMPLES = """
- name: Add KMIP server to VSP One Object
  hitachivantara.vspone_object.oneobject_node.hv_certificates:
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
      name: "test_kmip_server"
      host: "urloripaddressofkmipserver"
      port: 5696
      is_tls12_enabled: true
      kmip_protocol: "V1_3"
      https_ciphers: "TLS_RSA_WITH_AES_128_CBC_SHA256"

- name: Update a KMIP server from VSP One Object
  hitachivantara.vspone_object.oneobject_node.hv_kmip:
    connection_info:
      http_request_timeout: 300
      http_request_retry_times: 3
      http_request_retry_interval_seconds: 5
      cluster_name: "your_cluster_name"
      region: "your_region"
      oneobject_node_username: "your_username"
      oneobject_node_userpass: "your_password"
      oneobject_node_client_id: "vsp-object-external-client"
    state: "modify"
    spec:
      name: "test_kmip_server_update"
      host: "urloripaddressofkmipserver"
      port: 5696
      is_tls12_enabled: true
      kmip_protocol: "V1_3"
      https_ciphers: "TLS_RSA_WITH_AES_128_CBC_SHA256"
      uuid: "f2e39602-d960-4812-8c89-3b31212dfdca"

- name: Promote a KMIP server from VSP One Object
  hitachivantara.vspone_object.oneobject_node.hv_kmip:
    connection_info:
      http_request_timeout: 300
      http_request_retry_times: 3
      http_request_retry_interval_seconds: 5
      cluster_name: "your_cluster_name"
      region: "your_region"
      oneobject_node_username: "your_username"
      oneobject_node_userpass: "your_password"
      oneobject_node_client_id: "vsp-object-external-client"
    state: "promote"
    spec:
      name: "test_kmip_server"

- name: Delete a KMIP server from VSP One Object
  hitachivantara.vspone_object.oneobject_node.hv_kmip:
    connection_info:
      http_request_timeout: 300
      http_request_retry_times: 3
      http_request_retry_interval_seconds: 5
      cluster_name: "your_cluster_name"
      region: "your_region"
      oneobject_node_username: "your_username"
      oneobject_node_userpass: "your_password"
      oneobject_node_client_id: "vsp-object-external-client"
    state: "absent"
    spec:
      name: "test_kmip_server"
"""

RETURN = r"""
kmip_server:
  description: KMIP server and its attributes.
  returned: success
  type: dict
  contains:
    host:
      description: The host name or IP address of the KMIP server.
      type: str
      sample: "urloripaddressofkmipserver"
    https_ciphers:
      description: A string of comma-separated cyphers.
      type: str
      sample: "TLS_RSA_WITH_AES_128_CBC_SHA256"
    is_online:
      description: Whether the KMIP server is online.
      type: bool
      sample: false
    is_primary:
      description: Whether the KMIP server is the primary server.
      type: bool
      sample: true
    is_tls12_enabled:
      description: Whether TLS v1.2 is enabled on the KMIP server.
      type: bool
      sample: true
    kmip_protocol:
      description: The version of the KMIP protocol.
      type: str
      sample: "V1_3"
    name:
      description: The name of the KMIP server.
      type: str
      sample: "test_kmip_server"
    port:
      description: The port number of the KMIP server.
      type: int
      sample: 5696
    uuid:
      description: The UUID of the server.
      type: str
      sample: "f2e39602-d960-4812-8c89-3b31212dfdca"
"""


from ansible.module_utils.basic import AnsibleModule

from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.ansible_argument_spec_oo import (
    OOArgumentSpec,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.params_oo import (
    OOConnectionInfoParam, Tokens, KmipParam
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.gateway_oo import (
    OOGateway,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.kmip_servers import (
    KMIPServerResource,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.common_msg_catalog import (
    CommonMsgCatalog as CMCA,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.kmip_msg_catalog import (
    KmipMsgCatalog as KMCA,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


def main():
    logger = Log()

    fields = OOArgumentSpec.kmip()

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
    json_spec["state"] = module.params.pop("state", "")
    operation = json_spec.get("state", "")
    operation = operation.strip() if operation else ""

    operation = operation.lower()
    operation_map = {
        "present": "add",
        "absent": "delete",
        "promote": "promote",
        "modify": "modify"
    }

    input_params = None

    input_params = KmipParam(
        conn_info_param, json_spec
    )

    try:
        input_params.validate()
    except Exception as err:
        module.fail_json(msg=CMCA.ERR_VALIDATION.value.format(err))

    logger.writeDebug(
        "kmip_param={}".format(input_params)
    )

    raw_message = ""
    changed = True
    try:
        kmip_res = KMIPServerResource(
            input_params, tokens
        )
        raw_message, changed = kmip_res.kmip_operation()
    except Exception as err:
        err_msg = str(err)

        if hasattr(err, 'read'):
            err_msg = err.read().decode('utf-8')
        operation_value = operation_map.get(operation, "modify")

        module.fail_json(msg=KMCA.ERR_OP_KMIP.value.format(operation_value, err_msg))

    registration_message = validate_ansible_product_registration()
    response = {
        "changed": changed,
        "kmip_server": raw_message,
    }

    if registration_message:
        response["user_consent_required"] = registration_message

    module.exit_json(**response)

    # module.exit_json(changed=True, data=raw_message)


if __name__ == '__main__':
    main()
