# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)


DOCUMENTATION = """
---
module: hv_storage_class
short_description: Create or update a storage class
description:
  - This module creates or updates a storage class in Hitachi VSP One Object.
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
    description: Type of the storage class operation.
    type: str
    choices: ['present', 'default']
    required: false
  spec:
    description: Request parameters for creating or updating a storage class.
    type: dict
    required: true
    suboptions:
      name:
        description: The name of the storage class.
        type: str
        required: false
      data_count:
        description: The number of data blocks the system will use to store the data.
        type: int
        required: false
      parity_count:
        description: The number of parity blocks generated for redundancy.
        type: int
        required: false
      id:
        description: The ID of the storage class.
        type: str
        required: false
"""

EXAMPLES = """
- name: Create a storage class
  hitachivantara.vspone_object.oneobject_node.hv_storage_class:
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
      name: "TestStorageClassJul114"
      data_count: 1
      parity_count: 1

- name: Update a storage class
  hitachivantara.vspone_object.oneobject_node.hv_storage_class:
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
      name: "TestStorageClass"
      id: "-635732426"

- name: Update default storage class
  hitachivantara.vspone_object.oneobject_node.hv_storage_class:
    connection_info:
      http_request_timeout: 300
      http_request_retry_times: 3
      http_request_retry_interval_seconds: 5
      cluster_name: "your_cluster_name"
      region: "your_region"
      oneobject_node_username: "your_username"
      oneobject_node_userpass: "your_password"
      oneobject_node_client_id: "vsp-object-external-client"
    state: "default"
    spec:
      name: "TestStorageClassUpdated"
      id: "-635732426"
"""

RETURN = r"""
storage_class:
  description: Storage class and its attributes.
  returned: success
  type: dict
  contains:
    data_count:
      description: The number of data blocks the system will use to store the data.
      type: int
      sample: 1
    id:
      description: The ID of the storage class.
      type: int
      sample: -418384882
    name:
      description: The name of the storage class.
      type: str
      sample: "TestStorageClassJul114"
    parity_count:
      description: The number of parity blocks generated for redundancy.
      type: int
      sample: 1
"""


from ansible.module_utils.basic import AnsibleModule

from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.ansible_argument_spec_oo import (
    OOArgumentSpec,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.params_oo import (
    OOConnectionInfoParam, Tokens, CreateStorageClassParam, UpdateDefaultStorageClassParam, UpdateStorageClassParam,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.common_msg_catalog import (
    CommonMsgCatalog as CMCA,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.gateway_oo import (
    OOGateway,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.storage_classes import (
    StorageClassResource,
)

from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.storage_class_msg_catalog import (
    StorageClassMsgCatalog as SCMA,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


def main():
    logger = Log()

    fields = OOArgumentSpec.create_storage_class()

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

    is_create = False
    is_default_storage_class = False

    state = json_spec.pop("state", "")

    if json_spec["id"] is None and state != "default":
        json_spec.pop("id", None)
        logger.writeDebug("Creating new storage class")
        input_params = CreateStorageClassParam(
            conn_info_param, json_spec
        )
        is_create = True
    else:
        if state == "default":
            json_spec["is_default"] = True
        is_default_storage_class = json_spec.get('is_default', False)
        if is_default_storage_class:
            keys_to_remove = [key for key in json_spec if key != "id"]
            for key in keys_to_remove:
                del json_spec[key]
            input_params = UpdateDefaultStorageClassParam(
                conn_info_param, json_spec
            )
        else:
            input_params = UpdateStorageClassParam(
                conn_info_param, json_spec
            )

    try:
        input_params.validate()
    except Exception as err:
        module.fail_json(msg=CMCA.ERR_VALIDATION.value.format(err))

    logger.writeDebug(
        "create_storage_class_param={}".format(input_params)
    )
    changed = True
    raw_message = ""
    try:
        create_storage_class_res = StorageClassResource(
            input_params, tokens
        )
        if is_create:
            logger.writeDebug("Creating storage class")
            raw_message, changed = create_storage_class_res.create_one()
        else:
            if is_default_storage_class:
                logger.writeDebug("Updating default storage class")
                current_default_storage_class = create_storage_class_res.query_default()
                logger.writeDebug("Current default storage class {}".format(current_default_storage_class))
                if str(current_default_storage_class["id"]) == input_params.json_spec["id"]:
                    raw_message = current_default_storage_class
                    changed = False
                else:
                    raw_message, changed = create_storage_class_res.update_default()
            else:
                logger.writeDebug("Updating storage class")
                current_storage_class = create_storage_class_res.query_one()
                logger.writeDebug("Current storage class {}".format(current_storage_class))
                if current_storage_class["name"] != input_params.json_spec["name"]:
                    raw_message, changed = create_storage_class_res.update_one()
                else:
                    raw_message = current_storage_class
                    changed = False
    except Exception as err:
        module.fail_json(msg=SCMA.ERR_CREATE_UPDATE.value.format(err))

    registration_message = validate_ansible_product_registration()
    response = {
        "changed": changed,
        "storage_class": raw_message,
    }

    if registration_message:
        response["user_consent_required"] = registration_message

    module.exit_json(**response)

    # module.exit_json(changed=False, data=raw_message)


if __name__ == '__main__':
    main()
