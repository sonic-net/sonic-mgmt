# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)


DOCUMENTATION = """
---
module: hv_events_facts
short_description: Get events from VSP One Object
description:
  - This module query system or GMS events from Hitachi VSP One Object Node.
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
    description: Request parameters for fetching events.
    type: dict
    required: true
    suboptions:
      query_type:
        description: Defines which events needs to be fetched
        choices: ['GMS', 'SYSTEM']
        type: str
        required: true
      count:
        description: Number of Events to be fetched.
        type: int
        required: false
      severity:
        description: Event severity.
        type: str
        required: false
        choices: ['INFO', 'SEVERE', 'WARNING']
      user:
        description: ID of the user.
        type: int
        required: false
      start_timestamp:
        description: Date and time of the event from when it has to be fetched in the format yyyy-mm-ddThh:mm:ssZ.
        type: str
        required: false
      end_timestamp:
        description: Date and time of the event till when it has to be fetched in the format yyyy-mm-ddThh:mm:ssZ.
        type: str
        required: false
      category:
        description: A category the event falls into, such as user, bucket, KMIP and S3 settings.
        type: str
        required: false
      event_type_id:
        description: A unique identifier for a specific type of event.
        type: int
        required: false
"""

EXAMPLES = """
- name: Get system events
  hitachivantara.vspone_object.oneobject_node.hv_events_facts:
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
      query_type: "SYSTEM"
- name: Get GMS events
  hitachivantara.vspone_object.oneobject_node.hv_events_facts:
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
      query_type: "GMS"
"""

RETURN = r"""
ansible_facts:
    description: >
        Dictionary containing the discovered properties of the events.
    returned: always
    type: dict
    contains:
        events:
            description: List of events with their attributes.
            type: list
            elements: dict
            contains:
                category:
                    description: The category of the event.
                    type: str
                    sample: "STORAGE_COMPONENT"
                event_type_id:
                    description: The unique identifier for the event type.
                    type: str
                    sample: "10206"
                message:
                    description: A descriptive message about the event.
                    type: str
                    sample: "Failed to retrieve capacity usage"
                severity:
                    description: The severity level of the event.
                    type: str
                    sample: "SEVERE"
                subject:
                    description: The subject of the event.
                    type: str
                    sample: "Failed to Retrieve Storage Capacity"
                timestamp:
                    description: The timestamp when the event occurred.
                    type: str
                    sample: "2025-02-27T20:31:49.034Z"
                region_id:
                    description: The region identifier where the event occurred.
                    type: str
                    sample: "us-west-2"
"""

from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration, )
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.common_msg_catalog import (
    CommonMsgCatalog as CMCA, )
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.events import (
    SystemEventsResource, GMSEventsResource)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.gateway_oo import (
    OOGateway, )
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.params_oo import (
    OOConnectionInfoParam, Tokens, SystemEventsParam, GMSEventsParam)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.ansible_argument_spec_oo import (
    OOArgumentSpec, )
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible.module_utils.basic import AnsibleModule


def main():
    logger = Log()

    fields = OOArgumentSpec.events()

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
    logger.writeDebug("Bearer Tokens: {}".format(tokens.bearer_token))
    logger.writeDebug("XSRF Token: {}".format(tokens.xsrf_token))
    logger.writeDebug("vertx_session Token: {}".format(tokens.vertx_session))

    json_spec = module.params['spec']
    input_params = None

    if json_spec["query_type"] == "SYSTEM":
        input_params = SystemEventsParam(
            conn_info_param, json_spec
        )
    elif json_spec["query_type"] == "GMS":
        input_params = GMSEventsParam(
            conn_info_param, json_spec
        )

    logger.writeDebug(
        "event_param={}".format(input_params)
    )
    raw_message = ""
    try:
        if json_spec["query_type"] == "SYSTEM":
            json_spec.pop("query_type", None)
            events_res = SystemEventsResource(
                input_params, tokens
            )
        elif json_spec["query_type"] == "GMS":
            json_spec.pop("query_type", None)
            events_res = GMSEventsResource(
                input_params, tokens
            )
        raw_message = events_res.query_all()
        raw_message = raw_message.get("events", [])
    except Exception as err:
        module.fail_json(msg=CMCA.ERR_CMN_REASON.value.format(err))

    registration_message = validate_ansible_product_registration()
    response = {
        "events": raw_message,
    }

    if registration_message:
        response["user_consent_required"] = registration_message

    result = {
        "ansible_facts": response,
        "changed": False,
    }
    module.exit_json(**result)


if __name__ == '__main__':
    main()
