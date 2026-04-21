# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)


DOCUMENTATION = """
---
module: hv_storage_fault_domain
short_description: Create or update a storage fault domain
description:
  - This module creates or updates a storage fault domain in Hitachi VSP One Object.
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
    description: The state of the fault domain.
    type: str
    required: false
    choices: ['present']
  spec:
    description: Request parameters for fetching the storage fault domain.
    type: dict
    required: true
    suboptions:
      id:
        description: The unique identifier of the fault domain.
        type: str
        required: false
        default: ''
      name:
        description: The name of the fault domain.
        type: str
        required: false
      tags:
        description: The metadata tags associated with the fault domain.
        type: str
        required: false

"""

EXAMPLES = """
- name: Create a storage fault domain
  hitachivantara.vspone_object.oneobject_node.hv_storage_fault_domain:
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
      name: "TestStorageDomainJul114"

- name: Update a storage fault domain
  hitachivantara.vspone_object.oneobject_node.hv_storage_fault_domain:
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
      name: "TestStorageDomainJul112"
      id: "ersfdzv-635732426-34ewafs"
"""

RETURN = r"""
storage_fault_domain:
  description: Fault domain and its attributes.
  returned: success
  type: dict
  contains:
    id:
      description: The unique identifier of the storage fault domain.
      type: str
      sample: "3e119904-902a-4c2a-b8e1-f6654f55aab0"
    name:
      description: The name of the storage fault domain.
      type: str
      sample: "TestFaultDomain"
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.ansible_argument_spec_oo import (
    OOArgumentSpec,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.params_oo import (
    OOConnectionInfoParam, Tokens,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.storage_fault_domain_params_oo import (
    CreateStorageFaultDomainParam, UpdateStorageFaultDomainParam,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.gateway_oo import (
    OOGateway,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.storage_fault_domains import (
    StorageFaultDomainResource,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.storage_fault_domain_msg_catalog import (
    StorageFaultDomainMsgCatalog as SFDMC,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.common_msg_catalog import (
    CommonMsgCatalog as CMCA,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


def main():
    logger = Log()
    fields = OOArgumentSpec.create_update_storage_fault_domain()

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
    create_operation = True
    if json_spec:
        if json_spec["id"] == "":
            input_params = CreateStorageFaultDomainParam(
                conn_info_param, json_spec
            )
        else:
            create_operation = False
            input_params = UpdateStorageFaultDomainParam(
                conn_info_param, json_spec
            )
    else:
        module.fail_json(
            msg=CMCA.ERR_VALIDATION.value.format(
                SFDMC.ERR_INVALID_NAME_EMPTY.value))

    try:
        if input_params:
            input_params.validate()
    except Exception as err:
        module.fail_json(msg=CMCA.ERR_VALIDATION.value.format(err))

    logger.writeDebug(
        "storage_fault_domain_info_param={}".format(input_params)
    )
    raw_message = ""
    try:
        storage_fault_domains_res = StorageFaultDomainResource(
            input_params, tokens
        )
        fault_domain_list = storage_fault_domains_res.query_all()

        changed = True
        raw_data = None
        found_existing_name = False
        for fault_domain in fault_domain_list["storage_fault_domains"]:
            if storage_fault_domains_res.param.json_spec["name"] == fault_domain["name"]:
                found_existing_name = True
                raw_data = fault_domain
                break

        logger.writeDebug(
            "storage_fault_domain_info_param={}".format(input_params)
        )

        if create_operation:
            if found_existing_name:
                changed = False
                raw_message = raw_data
            else:
                raw_message = storage_fault_domains_res.create()
        else:
            do_update = True
            found_id = False
            logger.writeDebug("fault_domain_list: {}".format(fault_domain_list))
            for fault_domain in fault_domain_list["storage_fault_domains"]:
                if storage_fault_domains_res.param.json_spec["id"] == fault_domain["id"]:
                    found_id = True
                    storage_fault_domains_res_tags = storage_fault_domains_res.param.json_spec.get("tags", "")
                    fault_domain_tags = fault_domain.get("tags", "")
                    if storage_fault_domains_res.param.json_spec["name"] != fault_domain["name"]:
                        if found_existing_name:
                            do_update = False
                            raw_message = SFDMC.ERR_NAME_EXISTS.value.format(storage_fault_domains_res.param.json_spec["name"])
                    elif storage_fault_domains_res_tags == fault_domain_tags:
                        do_update = False
                        raw_message = raw_data
                    break
            if not found_id:
                raise ValueError(SFDMC.ERR_ID_NOT_EXIST.value)

            if do_update:
                logger.writeDebug(
                    "storage_fault_domain_info_param={}".format(input_params)
                )
                raw_message = storage_fault_domains_res.update()
            else:
                changed = False

    except Exception as err:
        module.fail_json(msg=CMCA.ERR_CMN_REASON.value.format(err))

    registration_message = validate_ansible_product_registration()
    response = {
        "changed": changed,
        "storage_fault_domain": raw_message,
    }

    if registration_message:
        response["user_consent_required"] = registration_message

    module.exit_json(**response)

    # module.exit_json(changed=False, data=raw_message)


if __name__ == '__main__':
    main()
