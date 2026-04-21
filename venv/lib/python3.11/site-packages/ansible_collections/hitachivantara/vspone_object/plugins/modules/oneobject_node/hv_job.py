# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)


DOCUMENTATION = """
---
module: hv_job
short_description: Manage jobs in Hitachi VSP One Object.
description:
  - This module manages jobs in Hitachi VSP One Object.
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
    description: The state of the job.
    type: str
    required: true
    choices: ['present', 'absent']
  spec:
    description: Request parameters for managing jobs.
    type: dict
    required: true
    suboptions:
      job_id:
        description: The ID of the job to manage.
        type: int
        required: false
      job_type:
        description: The type of the job to manage.
        type: str
        choices: ['BATCH_REPLICATE', 'LIFECYCLE_UPDATE', 'METRIC_RECONCILIATION', 'TRIGGER_RECONCILIATION']
        required: false
      bucket_name:
        description: The name of the bucket to operate on.
        type: str
        required: false
      job_parameters:
        description: Arbitrary parameters needed by different Job types.
        type: dict
        required: false
"""

EXAMPLES = """
- name: Create a job in VSP One Object
  hitachivantara.vspone_object.oneobject_node.hv_job:
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
      job_type: "BATCH_REPLICATE"
      bucket_name: "my_bucket"
      job_parameters:
        replication_filter: "ALL"

- name: Cancel a job in VSP One Object
  hitachivantara.vspone_object.oneobject_node.hv_job:
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
      job_id: 12345
"""

RETURN = r"""
job_info:
  description: Job information and its attributes.
  returned: success
  type: dict
  contains:
    job_id:
      description: Information about the job ID.
      type: dict
      contains:
        id:
          description: The unique identifier of the job.
          type: int
          sample: -769908758
    job_state:
      description: The current state of the job.
      type: str
      sample: "EXAMINING"
    job_type:
      description: The type of the job.
      type: str
      sample: "BATCH_REPLICATE"
"""


from ansible.module_utils.basic import AnsibleModule

from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.ansible_argument_spec_oo import (
    OOArgumentSpec,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.params_oo import (
    OOConnectionInfoParam, Tokens, CreateJobParam, CancelJobParam,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.common_msg_catalog import (
    CommonMsgCatalog as CMCA,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.gateway_oo import (
    OOGateway,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.job import (
    JobResource,
)

from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.job_msg_catalog import (
    JobMsgCatalog as JOBMCA,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


def main():
    logger = Log()

    fields = OOArgumentSpec.job_operation()

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
    create = False

    state = module.params.get('state', '')
    if state == 'present':
        create = True
        input_params = CreateJobParam(conn_info_param, json_spec)
        try:
            input_params.validate()
        except Exception as err:
            err_msg = str(err)
            module.fail_json(msg=err_msg)

    elif state == 'absent':
        input_params = CancelJobParam(conn_info_param, json_spec)
        try:
            input_params.validate()
        except Exception as err:
            err_msg = str(err)
            module.fail_json(msg=err_msg)
    else:
        module.fail_json(msg=CMCA.ERR_INVALID_STATE.value.format(state))

    logger.writeDebug(
        "input_params={}".format(input_params)
    )
    raw_message = ""
    changed = True
    try:
        if create:
            job_res = JobResource(
                input_params, tokens
            )
            raw_message = job_res.create_job()
            raw_message = raw_message.get("job_status", {})
        else:
            job_res = JobResource(
                input_params, tokens
            )
            raw_message = job_res.cancel_job()
            changed = raw_message.pop("changed", True)
            raw_message = raw_message.get("status", {})

    except Exception as err:
        err_msg = str(err)
        if hasattr(err, 'read'):
            err_msg = err.read().decode('utf-8')

        logger.writeError("Error occurred: {}".format(err_msg))
        if create:
            module.fail_json(msg=JOBMCA.ERR_CREATE_JOB.value.format(err_msg))
        else:
            module.fail_json(msg=JOBMCA.ERR_CANCEL_JOB.value.format(err_msg))

    registration_message = validate_ansible_product_registration()
    response = {
        "changed": changed,
        "job_status": raw_message,
    }

    if registration_message:
        response["user_consent_required"] = registration_message

    module.exit_json(**response)

    # module.exit_json(changed=True, data=raw_message)


if __name__ == '__main__':
    main()
