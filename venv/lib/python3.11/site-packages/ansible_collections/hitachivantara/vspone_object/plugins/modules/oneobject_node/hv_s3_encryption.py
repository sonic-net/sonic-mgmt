# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)


DOCUMENTATION = """
---
module: hv_s3_encryption
short_description: Set S3 Encryption
description:
  - This module sets S3 Encryption of Hitachi VSP One Object.
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
    description: The state of the encryption.
    type: str
    required: false
    choices: ['present']
  spec:
    description: Request parameters for setting S3 Encryption.
    type: dict
    required: true
    suboptions:
      encryption_mode:
        description:
          - Sets the S3 encryption mode.
          - You can set either INTERNAL or EXTERNAL.
          - Encryption is DISABLED by default.
        type: str
        required: true
"""

EXAMPLES = """
- name: Set S3 Encryption configuration
  hitachivantara.vspone_object.oneobject_node.hv_s3_encryption:
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
      encryption_mode: "INTERNAL"
"""

RETURN = r"""
encryption_info:
  description: Information about the encryption mode of Hitachi VSP One Object.
  returned: success
  type: dict
  contains:
    encryption_mode:
      description: The type of S3 encryption.
      type: str
      sample: "INTERNAL"
    rekey_events:
      description: Events from the rekeying process.
      type: list
      elements: dict
      contains:
        user:
          description: Displays the name of the user who set the encryption.
          type: str
          sample: "admin"
        timestamp:
          description: Displays the time when the encryption was applied.
          type: int
          sample: 1622547800
        code:
          description: A general reason for the rekey.
          type: str
          sample: "KEY_ROTATED"
        message:
          description: A message providing further explanation and the action required (if any) to remedy the error.
          type: str
          sample: "Encryption key was rotated successfully."
"""


from ansible.module_utils.basic import AnsibleModule

from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.ansible_argument_spec_oo import (
    OOArgumentSpec,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.params_oo import (
    OOConnectionInfoParam, Tokens, SetS3EncryptionParam,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.common_msg_catalog import (
    CommonMsgCatalog as CMCA,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.gateway_oo import (
    OOGateway,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.s3_encryption import (
    S3EncryptionResource,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.s3_encryption_msg_catalog import (
    S3EncryptionMsgCatalog as S3MC,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


def main():
    logger = Log()

    fields = OOArgumentSpec.set_s3_encryption()

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

    input_params = SetS3EncryptionParam(
        conn_info_param, json_spec
    )

    try:
        input_params.validate()
    except Exception as err:
        module.fail_json(msg=CMCA.ERR_VALIDATION.value.format(err))

    logger.writeDebug(
        "set_s3_encryption_param={}".format(input_params)
    )
    raw_message = ""
    try:
        set_s3_encryption_res = S3EncryptionResource(
            input_params, tokens
        )

        current_encryption = set_s3_encryption_res.get_s3_encryption()
        logger.writeDebug(
            "current_s3_encryption={}".format(input_params.json_spec)
        )

        # Check if the current encryption mode matches requested mode
        desired_mode = input_params.json_spec.get('encryption_mode', '')
        current_mode = current_encryption.get('encryption_mode', '')

        if current_mode == desired_mode:
            logger.writeDebug(f"S3 encryption is already configured with mode: {current_mode}")
            response = {
                "changed": False,
                "data": current_encryption,
            }
        else:
            raw_message = set_s3_encryption_res.set_s3_encryption()
            response = {
                "changed": True,
                "encryption_info": raw_message,
            }
    except Exception as err:
        module.fail_json(msg=S3MC.ERR_SET_ENCRYPTION_MODE.value.format(err))

    registration_message = validate_ansible_product_registration()

    if registration_message:
        response["user_consent_required"] = registration_message

    module.exit_json(**response)

    # module.exit_json(changed=True, data=raw_message)


if __name__ == '__main__':
    main()
