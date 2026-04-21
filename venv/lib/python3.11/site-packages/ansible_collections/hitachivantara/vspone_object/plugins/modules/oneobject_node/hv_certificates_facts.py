# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)


DOCUMENTATION = """
---
module: hv_certificates_facts
short_description: Get all the certificates of VSP One Object
description:
  - This module queries all the certificates from Hitachi VSP One Object.
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
    description: Optional request parameters for info of a certificate.
    type: dict
    required: false
    suboptions:
      subject_dn:
        description: The Subject Distinguished Name of the certificate.
        type: str
        required: false
"""

EXAMPLES = """
- name: List certificates
  hitachivantara.vspone_object.oneobject_node.hv_certificates_facts:
    connection_info:
      http_request_timeout: 300
      http_request_retry_times: 3
      http_request_retry_interval_seconds: 5
      cluster_name: "your_cluster_name"
      region: "your_region"
      oneobject_node_username: "your_username"
      oneobject_node_userpass: "your_password"
      oneobject_node_client_id: "vsp-object-external-client"

- name: Get info of a certificate
  hitachivantara.vspone_object.oneobject_node.hv_certificates_facts:
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
      subject_dn: "EMAILADDRESS=sample@example.com, CN=*.example.com, OU=SampleOU, O=SampleOrg, L=New York, ST=New York, C=US"
"""

RETURN = r"""
ansible_facts:
    description: >
        Dictionary containing the discovered properties of the certificates.
    returned: always
    type: dict
    contains:
        certificates:
            description: List of certificates with their attributes.
            type: list
            elements: dict
            contains:
                issuer_dn:
                    description: The Issuer Distinguished Name of the certificate.
                    type: str
                    sample: "CN=XXXXX, OU=XXXXX, O=XXXXX, L=XXXXX, ST=XXXXX, C=XXXXX"
                not_after:
                    description: The expiration date of the certificate.
                    type: str
                    sample: "9/6/2029 6:11PM"
                not_before:
                    description: The start date of the certificate.
                    type: str
                    sample: "9/6/2024 6:11PM"
                pem_encoded:
                    description: The status of the Privacy-Enhanced Mail (PEM) encoding of the certificate.
                    type: str
                    sample: "-----BEGIN CERTIFICATE----- SAMPLE DATA-----END CERTIFICATE-----"
                subject_dn:
                    description: The Subject Distinguished Name of the certificate.
                    type: str
                    sample: "CN=XXXXX, OU=XXXXX, O=XXXXX, L=XXXXX, ST=XXXXX, C=XXXXX"
"""


from ansible.module_utils.basic import AnsibleModule

from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.ansible_argument_spec_oo import (
    OOArgumentSpec,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.params_oo import (
    OOConnectionInfoParam, Tokens, CertificateParam
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.gateway_oo import (
    OOGateway,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.certificates import (
    CertificateResource,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.common_msg_catalog import (
    CommonMsgCatalog as CMCA,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.common.hv_utilities import (
    DictUtilities,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


def query_all(conn_info_param, tokens, logger, module):
    certificate_param = CertificateParam(
        conn_info_param, json_spec=None
    )

    logger.writeDebug(
        "certificate_param={}".format(certificate_param)
    )
    raw_message = ""
    try:
        certificates = CertificateResource(
            certificate_param, tokens
        )
        raw_message = certificates.query_all()
    except Exception as err:
        module.fail_json(msg=CMCA.ERR_CMN_REASON.value.format(err))

    registration_message = validate_ansible_product_registration()
    response = {
        "certificates": raw_message,
    }

    if registration_message:
        response["user_consent_required"] = registration_message

    result = {
        "ansible_facts": response,
        "changed": False,
    }
    module.exit_json(**result)

    # module.exit_json(changed=False, data=raw_message)


def query_one(json_spec, conn_info_param, tokens, logger, module):
    json_spec = DictUtilities.snake_to_camel(json_spec)
    logger.writeDebug("dict_json_spec={}".format(json_spec))

    input_params = CertificateParam(conn_info_param, json_spec)

    try:
        input_params.validate_query_one()
    except Exception as err:
        module.fail_json(msg=CMCA.ERR_VALIDATION.value.format(err))

    logger.writeDebug("input_params={}".format(input_params))
    raw_message = ""
    try:
        certificate_res = CertificateResource(input_params, tokens)
        raw_message = certificate_res.query_one()
    except Exception as err:
        err_msg = certificate_res.handle_error(err, query_one=True)
        module.fail_json(msg=CMCA.ERR_CMN_REASON.value.format(err_msg))

    registration_message = validate_ansible_product_registration()
    response = {
        "certificates": [raw_message],
    }

    if registration_message:
        response["user_consent_required"] = registration_message

    result = {
        "ansible_facts": response,
        "changed": False,
    }
    module.exit_json(**result)

    # module.exit_json(changed=False, data=raw_message)


def main():
    logger = Log()

    fields = OOArgumentSpec.certificate_info()

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

    json_spec = module.params.get('spec', None)

    if json_spec is not None:
        query_one(json_spec, conn_info_param, tokens, logger, module)
    else:
        query_all(conn_info_param, tokens, logger, module)


if __name__ == '__main__':
    main()
