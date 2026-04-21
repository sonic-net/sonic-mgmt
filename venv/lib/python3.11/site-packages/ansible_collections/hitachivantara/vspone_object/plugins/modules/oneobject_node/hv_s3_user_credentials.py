# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)


DOCUMENTATION = """
---
module: hv_s3_user_credentials
short_description: Generate S3 user credentials
description:
  - This module queries all the users from Hitachi VSP One Object.
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
      - Set operation to C(generate) for generating S3 user credentials.
      - Set operation to C(revoke) for revoking S3 user credentials.
    type: str
    choices: ['generate', 'revoke']
    required: true
  spec:
    description: Generate or revoke S3 user credentials.
    type: dict
    required: false
    suboptions:
      id:
        description: The ID of the user whose S3 credentials you are revoking.
        type: int
        required: false
"""

EXAMPLES = """
- name: Generate S3 user credentials
  hitachivantara.vspone_object.oneobject_node.hv_s3_user_credentials:
    connection_info:
      http_request_timeout: 300
      http_request_retry_times: 3
      http_request_retry_interval_seconds: 5
      cluster_name: "your_cluster_name"
      region: "your_region"
      oneobject_node_username: "your_username"
      oneobject_node_userpass: "your_password"
      oneobject_node_client_id: "vsp-object-external-client"
    state: generate

- name: Revoke s3 user credentials
  hitachivantara.vspone_object.oneobject_node.hv_s3_user_credentials:
    connection_info:
      http_request_timeout: 300
      http_request_retry_times: 3
      http_request_retry_interval_seconds: 5
      cluster_name: "your_cluster_name"
      region: "your_region"
      oneobject_node_username: "your_username"
      oneobject_node_userpass: "your_password"
      oneobject_node_client_id: "vsp-object-external-client"
    state: revoke
    spec:
      id: -618195248
"""

RETURN = r"""
user_credentials:
  description: Information about the S3 user credentials.
  returned: success
  type: dict
  contains:
    accessKey:
      description: The access key for the S3 user.
      type: str
      sample: "AKIAJpPOxSVfOqkJRRYQ"
    secretKey:
      description: The secret key for the S3 user.
      type: str
      sample: "OTVjMGQwNzQtMTFhMy00NGM5LTk2YjUtYTQ4YzI1"
    id:
      description: The ID of the S3 user.
      type: dict
      contains:
        id:
          description: The ID of the S3 user.
          type: int
          sample: -618195248
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.ansible_argument_spec_oo import (
    OOArgumentSpec,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.params_oo import (
    OOConnectionInfoParam, Tokens, GenerateS3UserCredentialsParam, RevokeS3UserCredentialsParam
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.gateway_oo import (
    OOGateway,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.users import (
    UserResource,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.common_msg_catalog import (
    CommonMsgCatalog as CMCA,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.users_msg_catalog import (
    UsersMsgCatalog as USERMCA,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


def main():
    logger = Log()

    fields = OOArgumentSpec.s3_user_credentials()

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
    input_params = None

    operation = module.params.get("state", "")
    if operation == "generate":
        input_params = GenerateS3UserCredentialsParam(
            conn_info_param, json_spec
        )
    elif operation == "revoke":
        input_params = RevokeS3UserCredentialsParam(
            conn_info_param, json_spec
        )
    else:
        logger.writeDebug(USERMCA.ERR_INVALID_OPERATION.value)
        module.fail_json(msg=USERMCA.ERR_INVALID_OPERATION.value)

    try:
        input_params.validate()
    except Exception as err:
        module.fail_json(msg=CMCA.ERR_VALIDATION.value.format(err))

    logger.writeDebug(
        "user_param={}".format(input_params)
    )

    raw_message = ""
    try:
        user_res = UserResource(
            input_params, tokens
        )
        if operation == "generate":
            raw_message, changed = user_res.generate_s3_credentials()
        elif operation == "revoke":
            users = user_res.get_all_users()
            if any(user["user_id"] == json_spec["id"] for user in users):
                raw_message, changed = user_res.revoke_s3_user(input_params.json_spec["id"])
            else:
                raise ValueError(USERMCA.ERR_ID_NOT_EXIST.value.format(json_spec["id"]))
    except ValueError as e:
        module.fail_json(msg=USERMCA.ERR_GENERATE_REVOKE_S3_CREDENTIALS.value.format(operation, e))
    except Exception as err:
        module.fail_json(msg=USERMCA.ERR_GENERATE_REVOKE_S3_CREDENTIALS.value.format(operation, err))

    registration_message = validate_ansible_product_registration()
    response = {
        "changed": True,
        "data": raw_message,
    }

    if registration_message:
        response["user_consent_required"] = registration_message

    module.exit_json(**response)

    # module.exit_json(changed=True, data=raw_message)


if __name__ == '__main__':
    main()
