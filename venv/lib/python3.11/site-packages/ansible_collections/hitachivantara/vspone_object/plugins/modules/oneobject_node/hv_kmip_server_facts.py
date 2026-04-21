# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)


DOCUMENTATION = """
---
module: hv_kmip_server_facts
short_description: Get a list of KMIP servers
description:
  - This module queries a list of all configured external KMIP servers.
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
    description: Request parameters for fetching kmip servers.
    type: dict
    required: false
    suboptions:
      name:
        description:
          - The user-assigned name of the KMIP server you want to get information about.
          - Type up to 63 Unicode characters.
        type: str
        required: false
"""

EXAMPLES = """
- name: List KMIP servers
  hitachivantara.vspone_object.oneobject_node.hv_kmip_server_facts:
    connection_info:
      http_request_timeout: 300
      http_request_retry_times: 3
      http_request_retry_interval_seconds: 5
      cluster_name: "your_cluster_name"
      region: "your_region"
      oneobject_node_username: "your_username"
      oneobject_node_userpass: "your_password"
      oneobject_node_client_id: "vsp-object-external-client"

- name: Get KMIP server by name
  hitachivantara.vspone_object.oneobject_node.hv_kmip_server_facts:
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
      name: "test_kmip_server"
"""

RETURN = r"""
ansible_facts:
    description: >
        Dictionary containing the discovered KMIP server facts.
    returned: always
    type: dict
    contains:
        kmip_servers:
            description: Contains detailed information about the KMIP servers.
            type: dict
            contains:
                servers:
                    description: Dictionary of KMIP servers keyed by their name.
                    type: dict
                    elements: dict
                    contains:
                        host:
                            description: The host name or IP address of the KMIP server.
                            type: str
                            sample: "urloripaddressofkmipserver"
                        https_ciphers:
                            description: A string of comma-separated cyphers.
                            type: str
                            sample: "TLS_RSA_WITH_AES_128_CBC_SHA256,TLS_AES_256_GCM_SHA384"
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
    OOConnectionInfoParam, Tokens, KMIPServerParam,
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

from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


def query_all_kmip_servers(conn_info_param, tokens, logger, module):
    input_params = KMIPServerParam(conn_info_param, json_spec=None)

    logger.writeDebug("storage_class_param={}".format(input_params))
    raw_message = ""
    try:
        kmip_servers_res = KMIPServerResource(input_params, tokens)
        raw_message = kmip_servers_res.query_all()
    except Exception as err:
        module.fail_json(msg=CMCA.ERR_CMN_REASON.value.format(err))

    registration_message = validate_ansible_product_registration()
    response = {
        "kmip_servers": raw_message,
    }

    if registration_message:
        response["user_consent_required"] = registration_message

    result = {
        "ansible_facts": response,
        "changed": False,
    }
    module.exit_json(**result)

    # module.exit_json(changed=False, data=raw_message)


def query_kmip_server_by_name(json_spec, conn_info_param, tokens, logger, module):
    input_params = KMIPServerParam(conn_info_param, json_spec=json_spec)

    try:
        input_params.validate()
    except Exception as err:
        module.fail_json(msg=CMCA.ERR_VALIDATION.value.format(err))

    raw_message = ""
    try:
        kmip_servers_res = KMIPServerResource(input_params, tokens)
        raw_message = kmip_servers_res.query_one()
    except Exception as err:
        module.fail_json(msg=CMCA.ERR_CMN_REASON.value.format(err.read()))

    registration_message = validate_ansible_product_registration()
    servers_dict = {}
    servers_dict["servers"] = {}
    server_name = raw_message.get("name", "server")
    servers_dict["servers"][server_name] = raw_message
    response = {
        "kmip_servers": servers_dict,
    }

    if registration_message:
        response["user_consent_required"] = registration_message

    result = {
        "ansible_facts": response,
        "changed": False,
    }

    module.exit_json(**result)


def main():
    logger = Log()

    fields = OOArgumentSpec.kmip_server_fact()

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
        bearer_token, xsrf_token, vertx_session = gw.get_tokens(conn_info_param)
    except Exception as err:
        logger.writeDebug(CMCA.AUTH_VALIDATION_ERR.value.format(err))
        module.fail_json(msg=CMCA.AUTH_VALIDATION_ERR.value.format(err))

    tokens = Tokens(bearer_token, xsrf_token, vertx_session)
    json_spec = module.params.get('spec', None)
    logger.writeDebug("dict_json_spec={}".format(json_spec))

    if json_spec is None:
        query_all_kmip_servers(conn_info_param, tokens, logger, module)
    else:
        query_kmip_server_by_name(json_spec, conn_info_param, tokens, logger, module)


if __name__ == '__main__':
    main()
