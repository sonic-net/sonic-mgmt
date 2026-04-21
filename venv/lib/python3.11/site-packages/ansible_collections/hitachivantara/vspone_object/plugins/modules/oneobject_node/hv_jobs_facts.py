#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)


DOCUMENTATION = """
---
module: hv_jobs_facts
short_description: Get job information from VSP One Object
description:
  - This module queries jobs from Hitachi VSP One Object.
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
    description: Request parameters for fetching jobs.
    type: dict
    required: false
    suboptions:
      query_type:
        choices: ["ALL", "STATUS"]
        description: Depends on if we need ALL Jobs list or STATUS of specific job
        type: str
        required: false
      page_size:
        description: Number of items to return in a page.
        type: int
        required: false
      job_id:
        description: UUID of the jobs.
        type: int
        required: false
      user_id:
        description: ID of the user.
        type: int
        required: false
      bucket_name:
        description: Bucket name.
        type: str
        required: false
"""

EXAMPLES = """
- name: Get all jobs
  hitachivantara.vspone_object.oneobject_node.hv_jobs_facts:
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
      user_id: -468170324
      bucket_name: "testbucket"

- name: Get job status
  hitachivantara.vspone_object.oneobject_node.hv_jobs_facts:
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
      job_id: -769908758
      query_type: "STATUS"

- name: Get n number of jobs
  hitachivantara.vspone_object.oneobject_node.hv_jobs_facts:
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
      user_id: -468170324
      bucket_name: "testbucket"
      page_size: 5
"""

RETURN = r"""
ansible_facts:
    description: >
        Dictionary containing the discovered properties of the jobs.
    returned: always
    type: dict
    contains:
        jobs:
            description: List of jobs with their attributes.
            type: list
            elements: dict
            contains:
                job_id:
                    description: The ID of the job.
                    type: dict
                    contains:
                        id:
                            description: The unique identifier of the job.
                            type: int
                            sample: -769908758
                job_state:
                    description: The current state of the job.
                    type: str
                    sample: "COMPLETE"
                job_type:
                    description: The type of job.
                    type: str
                    sample: "BATCH_REPLICATE"
                start_time:
                    description: The start time of the job.
                    type: float
                    sample: 1752770711.809
                complete_time:
                    description: The completion time of the job.
                    type: float
                    sample: 1752770724.423
                job_stats:
                    description: Statistics related to the job.
                    type: dict
                    contains:
                        failed:
                            description: Number of failed operations.
                            type: int
                            sample: 0
                        processed:
                            description: Number of processed items.
                            type: int
                            sample: 0
"""

from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.common_msg_catalog import (
    CommonMsgCatalog as CMCA, )
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.jobs import (
    JobsResource, )
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.gateway_oo import (
    OOGateway, )
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.params_oo import (
    OOConnectionInfoParam, Tokens, )
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.params_oo import (
    JobsStatusParam, JobsFactsParam, )
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.ansible_argument_spec_oo import (
    OOArgumentSpec, )
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.common.hv_log import (
    Log, )
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration, )
from ansible.module_utils.basic import AnsibleModule


def main():
    logger = Log()

    fields = OOArgumentSpec.jobs_facts()

    module = AnsibleModule(argument_spec=fields, supports_check_mode=True)
    connection_info = module.params['connection_info']

    # logger.writeDebug("connection_info: {}".format(connection_info))

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

    if json_spec is None:
        json_spec = {}
        json_spec["query_type"] = "ALL"

    if json_spec["query_type"] is None:
        json_spec["query_type"] = "ALL"

    logger.writeDebug("json_spec={}".format(json_spec))

    if json_spec["query_type"] == "STATUS":
        input_params = JobsStatusParam(
            conn_info_param, json_spec
        )
    elif json_spec["query_type"] == "ALL":
        logger.writeDebug("dict_json_spec={}".format(json_spec))
        input_params = JobsFactsParam(
            conn_info_param, json_spec
        )

    logger.writeDebug(
        "input_params={}".format(input_params)
    )

    try:
        if input_params:
            input_params.validate()
    except Exception as err:
        module.fail_json(msg=CMCA.ERR_VALIDATION.value.format(err))

    logger.writeDebug(
        "jobs_param={}".format(input_params)
    )
    raw_message = ""
    try:
        jobs_res = JobsResource(
            input_params, tokens
        )
        if json_spec["query_type"] == "STATUS":
            raw_message = jobs_res.query_status()
            raw_message = raw_message.get("status", {})
            raw_message = [raw_message]
        else:
            raw_message = jobs_res.query_all()
            raw_message = raw_message.get("jobs", [])
    except Exception as err:
        error_message = str(err)
        if hasattr(err, 'read'):
            error_message = err.read().decode('utf-8')
        logger.writeDebug("Error occurred: {}".format(error_message))
        module.fail_json(msg=CMCA.ERR_CMN_REASON.value.format(str(error_message)))

    registration_message = validate_ansible_product_registration()
    response = {
        "jobs": raw_message,
    }

    if registration_message:
        response["user_consent_required"] = registration_message

    result = {
        "ansible_facts": response,
        "changed": False
    }
    module.exit_json(**result)


if __name__ == '__main__':
    main()
