# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)


DOCUMENTATION = """
---
module: hv_galaxy_facts
short_description: Get the galaxy information of VSP One Object
description:
  - This module queries the galaxy information from Hitachi VSP One Object.
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
"""

EXAMPLES = """
- name: Retrieve galaxy information of VSP One Object system.
  hitachivantara.vspone_object.oneobject_node.hv_galaxy_facts:
    connection_info:
      http_request_timeout: 300
      http_request_retry_times: 3
      http_request_retry_interval_seconds: 5
      cluster_name: "your_cluster_name"
      region: "your_region"
      oneobject_node_username: "your_username"
      oneobject_node_userpass: "your_password"
      oneobject_node_client_id: "vsp-object-external-client"
"""

RETURN = r"""
ansible_facts:
    description: >
        Dictionary containing the discovered properties of the galaxy.
    returned: always
    type: dict
    contains:
        galaxy_info:
            description: Galaxy information of the Hitachi VSP One Object system.
            type: dict
            contains:
                product_short_name:
                    description: The short name of the product.
                    type: str
                    sample: "VSP One Object"
                galaxy_fqdn:
                    description: The Fully Qualified Domain Name (FQDN) of the galaxy.
                    type: str
                    sample: "vsp1o.example.com"
                gms_version:
                    description: The version of the GMS.
                    type: str
                    sample: "3.1.0.2025-06-13.07201-5b0ff7c3"
                regions:
                    description: The status of the Privacy-Enhanced Mail (PEM) encoding of the certificate.
                    type: list
                    elements: dict
                    contains:
                        name:
                            description: The name of the region.
                            type: str
                            sample: "us-west-1"
                        version:
                            description: Version of the GMS.
                            type: str
                            sample: "3.1.0.2025-06-13.07201-5b0ff7c3"
"""


from ansible.module_utils.basic import AnsibleModule

from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.ansible_argument_spec_oo import (
    OOArgumentSpec,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.params_oo import (
    OOConnectionInfoParam, Tokens, GalaxyInfoParam
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.gateway_oo import (
    OOGateway,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.galaxy import (
    GalaxyResource,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.common_msg_catalog import (
    CommonMsgCatalog as CMCA,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


def main():
    logger = Log()

    fields = OOArgumentSpec.connection_info()

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

    galaxy_info_param = GalaxyInfoParam(
        conn_info_param, json_spec=None
    )

    logger.writeDebug(
        "galaxy_info_param={}".format(galaxy_info_param)
    )
    raw_message = ""
    try:
        galaxy = GalaxyResource(
            galaxy_info_param, tokens
        )
        raw_message = galaxy.query_galaxy()
    except Exception as err:
        module.fail_json(msg=CMCA.ERR_CMN_REASON.value.format(err))

    registration_message = validate_ansible_product_registration()
    response = {
        "galaxy_info": raw_message,
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
