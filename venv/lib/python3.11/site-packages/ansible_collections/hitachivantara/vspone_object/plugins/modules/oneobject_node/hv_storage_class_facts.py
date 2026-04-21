# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)


DOCUMENTATION = """
---
module: hv_storage_class_facts
short_description: Get storage classes from VSP One Object
description:
  - This module queries storage classes from Hitachi VSP One Object.
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
    description: Optional request parameters for fetching storage class information.
    type: dict
    required: false
    suboptions:
      page_size:
        description: The maximum amount of domains to return in a single response.
        type: int
        required: false
      id:
        description: The ID of the storage class.
        type: str
        required: false
      query_type:
        description:
          - Set state to C(regular) for fetching regular storage classes
          - Set state to C(default) for fetching default storage class
        type: str
        required: false
        choices: ['regular','default']
        default: 'regular'
"""

EXAMPLES = """
- name: Get Storage Classes
  hitachivantara.vspone_object.oneobject_node.hv_storage_class_facts:
    connection_info:
      http_request_timeout: 300
      http_request_retry_times: 3
      http_request_retry_interval_seconds: 5
      cluster_name: "your_cluster_name"
      region: "your_region"
      oneobject_node_username: "your_username"
      oneobject_node_userpass: "your_password"
      oneobject_node_client_id: "vsp-object-external-client"

- name: Get info of a storage class
  hitachivantara.vspone_object.oneobject_node.hv_storage_class_facts:
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
      id: 1169621510

- name: Get n storage classes
  hitachivantara.vspone_object.oneobject_node.hv_storage_class_facts:
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

- name: Get default storage class
  hitachivantara.vspone_object.oneobject_node.hv_storage_class_facts:
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
      query_type: "default"
"""

RETURN = r"""
ansible_facts:
    description: >
        Dictionary containing the discovered properties of the storage classes.
    returned: always
    type: dict
    contains:
        storage_class_summary:
            description: Summary of storage classes in the Hitachi VSP One Object system.
            type: list
            elements: dict
            contains:
                storage_classes:
                    description: List of storage classes.
                    type: list
                    elements: dict
                    contains:
                        id:
                            description: The ID of the storage class.
                            type: int
                            sample: 194783998
                        name:
                            description: The name of the storage class.
                            type: str
                            sample: "StandardClass"
                        data_count:
                            description: The number of data fragments of the storage class.
                            type: int
                            sample: 1
                        parity_count:
                            description: The number of parity fragments of the storage class.
                            type: int
                            sample: 1
                storage_components:
                    description:
                        - List of storage components associated with the storage classes.
                        - Refer to M(hitachivantara.vspone_object.oneobject_node.hv_storage_components_facts) for more details.
                    type: list
                    elements: dict
                    sample: []
                page_token:
                    description: Token for pagination.
                    type: str
                    sample: "eyJ2ZXJzaW9uIjoxL"
"""
# Not including storage component details due to length constraints.

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.common.ansible_common_constants import (
    DEFAULT_STORAGE_CLASS_PAGE_SIZE,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.ansible_argument_spec_oo import (
    OOArgumentSpec,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.params_oo import (
    OOConnectionInfoParam, Tokens, StorageClassParam, StorageClassInfoParam,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.gateway_oo import (
    OOGateway,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.storage_classes import (
    StorageClassResource,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.common_msg_catalog import (
    CommonMsgCatalog as CMCA,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.common.hv_utilities import (
    DictUtilities,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.common.hv_constants import (
    StorageClassConstants as SCC,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


def query_all_storage_classes(conn_info_param, tokens, logger, module):
    json_spec = {}
    json_spec['pageSize'] = DEFAULT_STORAGE_CLASS_PAGE_SIZE
    input_params = StorageClassParam(conn_info_param, json_spec)

    try:
        input_params.validate()
    except Exception as err:
        module.fail_json(msg=CMCA.ERR_VALIDATION.value.format(err))

    logger.writeDebug("storage_class_param={}".format(input_params))
    raw_message = ""
    try:
        storage_classes_res = StorageClassResource(input_params, tokens)
        raw_message = storage_classes_res.query_all()
    except Exception as err:
        module.fail_json(msg=CMCA.ERR_CMN_REASON.value.format(err))

    registration_message = validate_ansible_product_registration()
    response = {
        "storage_class_summary": raw_message,
    }

    if registration_message:
        response["user_consent_required"] = registration_message

    result = {
        "ansible_facts": response,
        "changed": False,
    }
    module.exit_json(**result)

    # module.exit_json(changed=False, data=raw_message)


def query_n_storage_class(json_spec, conn_info_param, tokens, logger, module):
    input_params = StorageClassInfoParam(conn_info_param, json_spec)

    try:
        input_params.validate()
    except Exception as err:
        module.fail_json(msg=CMCA.ERR_VALIDATION.value.format(err))

    logger.writeDebug("storage_class_info_param={}".format(input_params))
    raw_message = ""
    query_one = True
    try:
        storage_classes_res = StorageClassResource(input_params, tokens)
        if json_spec.get('pageSize', None) is not None:
            query_one = False
            raw_message = storage_classes_res.query_n()
        else:
            raw_message = storage_classes_res.query_one()
            storage_class = extract_raw_message(raw_message)
            raw_message["storage_classes"] = storage_class
            raw_message.pop("data_count", None)
            raw_message.pop("id", None)
            raw_message.pop("name", None)
            raw_message.pop("parity_count", None)
    except Exception as err:
        err_msg = err
        err_msg = storage_classes_res.handle_error(err, query_one)
        module.fail_json(msg=CMCA.ERR_CMN_REASON.value.format(err_msg))

    registration_message = validate_ansible_product_registration()
    response = {
        "storage_class_summary": raw_message,
    }

    if registration_message:
        response["user_consent_required"] = registration_message

    result = {
        "ansible_facts": response,
        "changed": False,
    }
    module.exit_json(**result)

    # module.exit_json(changed=False, data=raw_message)


def query_default_storage_class(json_spec, conn_info_param, tokens, logger, module):
    input_params = StorageClassInfoParam(conn_info_param, json_spec)

    raw_message = ""
    try:
        storage_class_res = StorageClassResource(input_params, tokens)
        raw_message = storage_class_res.query_default()
    except Exception as err:
        logger.writeDebug("query_default_storage_class err={}".format(err))
        module.fail_json(msg=CMCA.ERR_CMN_REASON.value.format(err))

    registration_message = validate_ansible_product_registration()
    storage_classes_dict = {}
    storage_classes_dict['storage_classes'] = [raw_message]
    response = {
        "storage_class_summary": storage_classes_dict,
    }

    if registration_message:
        response["user_consent_required"] = registration_message

    result = {
        "ansible_facts": response,
        "changed": False,
    }
    module.exit_json(**result)

    # module.exit_json(changed=False, data=raw_message)


def clean_spec(json_spec):
    json_spec = DictUtilities.snake_to_camel(json_spec)
    ignore_spec_list = ["id"]
    json_spec = {k: v for k, v in json_spec.items() if v is not None
                 or k in ignore_spec_list}
    json_spec = DictUtilities.delete_keys(json_spec, SCC.NON_MAPI_SPEC_PARAMS)
    return json_spec


def extract_raw_message(raw_message):
    if raw_message is None or not isinstance(raw_message, dict):
        return []
    storage_class_info = {}
    data_count = raw_message.get("data_count", None)
    id = raw_message.get("id", None)
    name = raw_message.get("name", None)
    parity_count = raw_message.get("parity_count", None)

    storage_class_info['id'] = id
    storage_class_info['name'] = name
    storage_class_info['data_count'] = data_count
    storage_class_info['parity_count'] = parity_count

    return [storage_class_info]


def main():
    logger = Log()

    fields = OOArgumentSpec.storage_class_fact()

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
        query_all_storage_classes(conn_info_param, tokens, logger, module)
    else:
        json_spec_obj = DictUtilities.snake_to_camel(json_spec)
        input_params_obj = StorageClassInfoParam(conn_info_param, json_spec_obj)

        try:
            query_type_default = input_params_obj.default_query_type()
        except Exception as err:
            module.fail_json(msg=CMCA.ERR_VALIDATION.value.format(err))

        json_spec = clean_spec(json_spec)
        logger.writeDebug("dict_json_spec={}".format(json_spec))
        if query_type_default:
            query_default_storage_class(json_spec, conn_info_param, tokens, logger, module)
        else:
            if len(json_spec) == 0:
                query_all_storage_classes(conn_info_param, tokens, logger, module)
            else:
                query_n_storage_class(json_spec, conn_info_param, tokens, logger, module)


if __name__ == '__main__':
    main()
