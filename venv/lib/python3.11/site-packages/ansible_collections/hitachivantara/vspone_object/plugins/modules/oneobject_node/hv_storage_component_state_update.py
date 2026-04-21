# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)


DOCUMENTATION = """
---
module: hv_storage_component_state_update
short_description: Update state of a storage component
description:
  - This module updates state of a storage component on Hitachi VSP One Object.
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
    description: The state of the storage component.
    type: str
    required: false
    choices: ['present']
  spec:
    description: Update storage component state.
    type: dict
    required: true
    suboptions:
      storage_component_state:
        description:
          - Set operation to C(ACTIVE) for activating storage component
          - Set operation to C(PAUSED) for testing storage component connection
          - Set operation to C(READ_ONLY) for creating or updating storage component
          - Set operation to C(DECOMMISSION) for decommissioning storage component
        choices: ['ACTIVE', 'PAUSED', 'READ_ONLY', 'DECOMMISSION']
        type: str
        required: true
      id:
        description: The ID of the storage component.
        type: str
        required: true
"""

EXAMPLES = """
- name: Update a storage component state
  hitachivantara.vspone_object.oneobject_node.hv_storage_component_state_update:
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
      storage_component_state: "PAUSED"
      id: -418384882
"""

RETURN = r"""
storage_component_status:
  description: Storage component status and its attributes.
  returned: success
  type: dict
  contains:
    http_status:
      description: The HTTP status code returned by the API.
      type: int
      sample: 1
    id:
      description: The ID of the storage class.
      type: int
      sample: -418384882
    state:
      description: The current state of the storage component.
      type: str
      sample: "ACTIVE"
    storage_type:
      description: The type of the storage component.
      type: str
      sample: "HCPS_S3"
    verified:
      description: Whether the storage component has been verified.
      type: bool
      sample: true
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration, )
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.common.hv_constants import (
    StorageComponentConstants as SCC, )
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.ansible_argument_spec_oo import (
    OOArgumentSpec, )
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.params_oo import (
    OOConnectionInfoParam, Tokens, StorageComponentUpdateStateParam, )
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.common_msg_catalog import (
    CommonMsgCatalog as CMCA, )
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.gateway_oo import (
    OOGateway, )
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.storage_components import (
    StorageComponentResource, )
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.storage_components_msg_catalog import (
    StorageComponentMsgCatalog as SCMA, )


def main():
    logger = Log()

    fields = OOArgumentSpec.storage_component_state_update()

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

    input_params = StorageComponentUpdateStateParam(conn_info_param, json_spec)

    try:
        if input_params:
            input_params.validate()
    except Exception as err:
        module.fail_json(msg=CMCA.ERR_VALIDATION.value.format(err))

    logger.writeDebug(
        "storage_component_state_update_param={}".format(input_params)
    )
    raw_message = ""
    changed = False
    try:
        storage_component_res = StorageComponentResource(
            input_params, tokens
        )
        found_id = False
        storage_component_list = storage_component_res.query_all_no_params()
        storage_component_list = storage_component_list.get("storage_components", [])
        logger.writeDebug(
            "storage_component_list={}".format(storage_component_list)
        )
        for storage_component in storage_component_list:
            if int(storage_component["id"]) == int(json_spec["id"]):
                found_id = True

        if not found_id:
            raw_message = SCMA.ERR_ID_NOT_FOUND.value.format(json_spec["id"])
        else:
            if json_spec['storage_component_state'] == SCC.CONVERSION_STATE_DECOMMISSION:
                raw_message = storage_component_res.decomission_storage_component()
                changed = raw_message.pop("changed", False)
            else:
                raw_message = storage_component_res.update_storage_component_state()
                changed = raw_message.pop("changed", False)
    except Exception as err:
        module.fail_json(
            msg=SCMA.ERR_UPDATE_STATE_STORAGE_COMPONENT.value.format(err))

    registration_message = validate_ansible_product_registration()
    response = {
        "changed": changed,
        "storage_component_status": raw_message,
    }

    if registration_message:
        response["user_consent_required"] = registration_message

    module.exit_json(**response)

    # module.exit_json(changed=True, data=raw_message)


if __name__ == '__main__':
    main()
