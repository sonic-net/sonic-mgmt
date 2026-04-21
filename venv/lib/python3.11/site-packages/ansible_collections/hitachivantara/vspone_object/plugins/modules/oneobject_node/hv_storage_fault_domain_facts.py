#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)


DOCUMENTATION = """
---
module: hv_storage_fault_domain_facts
short_description: Get storage fault domains from VSP One Object
description:
  - This module queries storage fault domains from Hitachi VSP One Object.
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
    description: Request parameters for fetching storage fault domain.
    type: dict
    required: false
    suboptions:
      page_size:
        description: The maximum amount of domains to return in a single response.
        type: int
        required: false
      id:
        description: The unique identifier of the fault domain.
        type: str
        required: false
"""

EXAMPLES = """
- name: List storage fault domains
  hitachivantara.vspone_object.oneobject_node.hv_storage_fault_domain_facts:
    connection_info:
      http_request_timeout: 300
      http_request_retry_times: 3
      http_request_retry_interval_seconds: 5
      cluster_name: "your_cluster_name"
      region: "your_region"
      oneobject_node_username: "your_username"
      oneobject_node_userpass: "your_password"
      oneobject_node_client_id: "vsp-object-external-client"

- name: Get info of a storage fault domain
  hitachivantara.vspone_object.oneobject_node.hv_storage_fault_domain_facts:
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
      id: "17fb8b61-e012-419d-b460-7863106dbe03"

- name: Get n number of storage fault domains
  hitachivantara.vspone_object.oneobject_node.hv_storage_fault_domain_facts:
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
      page_size: 5
"""

RETURN = r"""
ansible_facts:
    description: >
        Dictionary containing the discovered properties of the fault domains.
    returned: always
    type: dict
    contains:
        storage_fault_domain_summary:
            description: Summary of fault domains in the Hitachi VSP One Object system.
            type: list
            elements: dict
            contains:
                storage_fault_domains:
                    description: List of storage fault domains.
                    type: list
                    elements: dict
                    contains:
                        id:
                            description: The unique identifier of the fault domain.
                            type: int
                            sample: 194783998
                        name:
                            description: The name of the fault domain.
                            type: str
                            sample: "TestFaultDomain"
                        tags:
                            description: The metadata tags associated with the fault domain.
                            type: str
                            sample: "sample_tag"
                storage_components:
                    description:
                        - List of storage components associated with the fault domain.
                        - Refer to M(hitachivantara.vspone_object.oneobject_node.hv_storage_components_facts) for more details.
                    type: list
                    elements: dict
                    sample: []
                page_token:
                    description: Token for pagination.
                    type: str
                    sample: "eyJ2ZXJzaW9uIjoxL"
"""

from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.common_msg_catalog import (
    CommonMsgCatalog as CMCA, )
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.common.hv_constants import (
    StorageFaultDomainConstants as SCC, )
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.common.hv_utilities import (
    DictUtilities, )
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.storage_fault_domains import (
    StorageFaultDomainResource, )
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.gateway_oo import (
    OOGateway, )
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.params_oo import (
    OOConnectionInfoParam, Tokens, )
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.storage_fault_domain_params_oo import (
    StorageFaultDomainInfoParam, StorageFaultDomainParam, )
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.ansible_argument_spec_oo import (
    OOArgumentSpec, )
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.common.ansible_common_constants import (
    DEFAULT_STORAGE_FAULT_DOMAIN_PAGE_SIZE, )
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)
from ansible.module_utils.basic import AnsibleModule


def clean_spec(json_spec):
    json_spec = DictUtilities.snake_to_camel(json_spec)
    ignore_spec_list = ["id"]
    json_spec = {k: v for k, v in json_spec.items() if v is not None
                 or k in ignore_spec_list}
    json_spec = DictUtilities.delete_keys(json_spec, SCC.NON_MAPI_SPEC_PARAMS)
    return json_spec


def main():
    logger = Log()

    fields = OOArgumentSpec.storage_fault_domain_facts()

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
        bearer_token, xsrf_token, vertx_session = gw.get_tokens(
            conn_info_param)
    except Exception as err:
        logger.writeDebug(CMCA.AUTH_VALIDATION_ERR.value.format(err))
        module.fail_json(msg=CMCA.AUTH_VALIDATION_ERR.value.format(err))

    tokens = Tokens(bearer_token, xsrf_token, vertx_session)
    json_spec = module.params['spec']

    input_params = None

    if not json_spec:
        json_spec = dict()
        json_spec["pageSize"] = DEFAULT_STORAGE_FAULT_DOMAIN_PAGE_SIZE
        input_params = StorageFaultDomainParam(
            conn_info_param, json_spec
        )
    else:
        json_spec_obj = DictUtilities.snake_to_camel(json_spec)
        json_spec = clean_spec(json_spec_obj)
        logger.writeDebug("dict_json_spec={}".format(json_spec))

        if len(json_spec) == 0:
            json_spec["pageSize"] = DEFAULT_STORAGE_FAULT_DOMAIN_PAGE_SIZE
            input_params = StorageFaultDomainParam(
                conn_info_param, json_spec
            )
        else:
            input_params = StorageFaultDomainInfoParam(
                conn_info_param, json_spec
            )

    try:
        if input_params:
            input_params.validate()
    except Exception as err:
        module.fail_json(msg=CMCA.ERR_VALIDATION.value.format(err))

    logger.writeDebug(
        "storage_fault_domain_param={}".format(input_params)
    )
    raw_message = ""
    query_one = False
    try:
        storage_fault_domain_res = StorageFaultDomainResource(
            input_params, tokens
        )
        if json_spec.get('pageSize', None) is not None:
            if json_spec.get(
                'pageSize',
                    None) == DEFAULT_STORAGE_FAULT_DOMAIN_PAGE_SIZE:
                raw_message = storage_fault_domain_res.query_all()
            else:
                raw_message = storage_fault_domain_res.query_n()
        else:
            query_one = True
            raw_message = storage_fault_domain_res.query_one()
    except Exception as err:
        err_msg = err
        err_msg = storage_fault_domain_res.handle_error(err, query_one)
        module.fail_json(msg=CMCA.ERR_CMN_REASON.value.format(err_msg))

    registration_message = validate_ansible_product_registration()
    storage_fault_domains = raw_message

    if query_one:
        storage_fault_domain = [raw_message]
        storage_fault_domains = {
            "storage_fault_domains": storage_fault_domain
        }

    response = {
        "storage_fault_domain_summary": storage_fault_domains,
    }

    if registration_message:
        response["user_consent_required"] = registration_message

    result = {
        "ansible_facts": response,
        "changed": False,
    }
    module.exit_json(**result)

    # module.exit_json(changed=False, data=raw_message)


if __name__ == '__main__':
    main()
