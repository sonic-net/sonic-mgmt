# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)

# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)


DOCUMENTATION = """
---
module: hv_certificates
short_description: Manage certificates in Hitachi VSP One Object
description:
  - This module manages certificates in Hitachi VSP One Object.
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
    description: Desired state of the certificate.
    type: str
    required: false
    choices: ['present', 'absent']
  spec:
    description: Request parameters for managing certificates.
    type: dict
    required: true
    suboptions:
      cert_file_path:
        description:
          - Path to the certificate file.
          - If provided, the module will add the certificate from this file.
        type: str
        required: false
      delete_cert_dn:
        description:
          - The Subject Distinguished Name of the certificate.
          - If provided, the module will delete the certificate with this DN.
        type: str
        required: false
"""

EXAMPLES = """
- name: Add Certificate to VSP One Object
  hitachivantara.vspone_object.oneobject_node.hv_certificates:
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
      cert_file_path: "/path/to/certificate.pem"

- name: Delete a certificate from VSP One Object
  hitachivantara.vspone_object.oneobject_node.hv_certificates:
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
certificate:
  description: Certificate and its attributes.
  returned: success
  type: dict
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
    OOConnectionInfoParam, Tokens, CertificateOpParam
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
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.certificate_msg_catalog import (
    CertificateMsgCatalog as CERTMCA,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


def main():
    logger = Log()

    fields = OOArgumentSpec.certificate()

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
    json_spec["state"] = module.params.get("state", None)

    input_params = CertificateOpParam(
        conn_info_param, json_spec
    )

    try:
        input_params.validate()
    except Exception as err:
        module.fail_json(msg=CMCA.ERR_VALIDATION.value.format(err))

    logger.writeDebug(
        "cert_op_param={}".format(input_params)
    )
    cert_file_path = json_spec.get("cert_file_path", None)
    delete_cert_dn = json_spec.get("delete_cert_dn", None)
    cert_res = CertificateResource(
        input_params, tokens
    )
    raw_message = ""
    changed = True

    if cert_file_path is not None and cert_file_path.strip() != "":
        try:
            raw_message, changed = cert_res.add_cert()
        except Exception as err:
            module.fail_json(msg=CERTMCA.ERR_ADD.value.format(err))

    elif delete_cert_dn is not None and delete_cert_dn != "":
        try:
            raw_message = cert_res.delete_cert()
        except Exception as err:
            module.fail_json(msg=CERTMCA.ERR_DELETE.value.format(err))

    registration_message = validate_ansible_product_registration()
    response = {
        "changed": changed,
        "certificate": raw_message,
    }

    if registration_message:
        response["user_consent_required"] = registration_message

    module.exit_json(**response)

    # module.exit_json(changed=True, data=raw_message)


if __name__ == '__main__':
    main()
