# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)


DOCUMENTATION = """
---
module: hv_user_id_facts
short_description: Get all the users's ids of VSP One Object
description:
  - This module queries all the users's ids from Hitachi VSP One Object.
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
    description: Request parameters for fetching user id information.
    type: dict
    required: false
    suboptions:
      user_uuid:
        description: Keycloak user UUID of the user.
        type: str
        required: false
"""

EXAMPLES = """
- name: Get list of all users
  hitachivantara.vspone_object.oneobject_node.hv_user_id_facts:
    connection_info:
      http_request_timeout: 300
      http_request_retry_times: 3
      http_request_retry_interval_seconds: 5
      cluster_name: "your_cluster_name"
      region: "your_region"
      oneobject_node_username: "your_username"
      oneobject_node_userpass: "your_password"
      oneobject_node_client_id: "vsp-object-external-client"

- name: Retrieve keycloak user information
  hitachivantara.vspone_object.oneobject_node.hv_user_id_facts:
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
      user_uuid: "b584795a-a9c9-4e89-a96b-0ffb4489dad9"
"""

RETURN = r"""
ansible_facts:
    description: >
        Dictionary containing the discovered properties of the users.
    returned: always
    type: dict
    contains:
        users:
            description: List of users with their attributes.
            type: list
            elements: dict
            contains:
                user_id:
                    description: The ID of the user.
                    type: int
                    sample: 1852773175
                user_name:
                    description: The display name of the user.
                    type: str
                    sample: "test_user"
                user_uuid:
                    description: The UUID of the user.
                    type: str
                    sample: "e696b93c-840a-4ba4-858e-4086a6034a5c"
        keycloak_user:
            description: Keycloak user information.
            type: dict
            contains:
                id:
                    description: The ID of the user.
                    type: dict
                    contains:
                        id:
                            description: The ID of the user.
                            type: str
                            sample: -6786763175
                idp_id:
                    description: The ID of the identity provider.
                    type: str
                    sample: "e696b93c-840a-4ba4-858e-4086a6034a5c"
"""


from ansible.module_utils.basic import AnsibleModule

from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.ansible_argument_spec_oo import (
    OOArgumentSpec,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.params_oo import (
    OOConnectionInfoParam, Tokens, UserIdParam
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
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


def main():
    logger = Log()

    fields = OOArgumentSpec.user_id()

    module = AnsibleModule(argument_spec=fields, supports_check_mode=True)
    connection_info = module.params['connection_info']
    json_spec = module.params['spec']

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
    user_param = None
    validation = False

    logger.writeDebug("spec: {}".format(json_spec))

    if json_spec is not None:
        logger.writeDebug("json_spec: {}".format(json_spec))
        user_param = UserIdParam(
            conn_info_param, json_spec=json_spec
        )
        try:
            validation = True
            user_param.validate()
        except Exception as err:
            module.fail_json(msg=CMCA.ERR_VALIDATION.value.format(err))
    else:
        user_param = UserIdParam(
            conn_info_param, json_spec=None
        )
    logger.writeDebug(
        "user_param={}".format(user_param)
    )
    raw_message = ""
    if validation:
        try:
            users = UserResource(
                user_param, tokens
            )
            raw_message = users.get_user()
            users_dict = {}
            users_dict["keycloak_user"] = raw_message
        except Exception as err:
            module.fail_json(msg=CMCA.ERR_CMN_REASON.value.format(err))
    else:
        try:
            users = UserResource(
                user_param, tokens
            )
            raw_message = users.get_all_users()
            users_dict = {}
            users_dict["users"] = raw_message
        except Exception as err:
            module.fail_json(msg=CMCA.ERR_CMN_REASON.value.format(err))

    registration_message = validate_ansible_product_registration()
    response = {
        "changed": False,
        "ansible_facts": users_dict,
    }

    if registration_message:
        response["user_consent_required"] = registration_message

    module.exit_json(**response)

    # module.exit_json(changed=False, data=raw_message)


if __name__ == '__main__':
    main()
