#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: intersight_certificate_management_policy
short_description: Certificate Management Policy configuration for Cisco Intersight
description:
  - Manages Certificate Management Policy configuration on Cisco Intersight.
  - A policy to configure certificate management for Cisco Intersight managed servers.
  - This policy allows configuration of Root CA certificates and IMC certificates with private keys.
  - For more information see L(Cisco Intersight,https://intersight.com/apidocs/certificatemanagement/Policies/get/).
extends_documentation_fragment: intersight
options:
  state:
    description:
      - If C(present), will verify the resource is present and will create if needed.
      - If C(absent), will verify the resource is absent and will delete if needed.
    type: str
    choices: [present, absent]
    default: present
  organization:
    description:
      - The name of the Organization this resource is assigned to.
      - Profiles and Policies that are created within a Custom Organization are applicable only to devices in the same Organization.
    type: str
    default: default
  name:
    description:
      - The name assigned to the Certificate Management Policy.
      - The name must be between 1 and 62 alphanumeric characters, allowing special characters :-_.
    type: str
    required: true
  description:
    description:
      - The user-defined description for the Certificate Management Policy.
      - Description can contain letters(a-z, A-Z), numbers(0-9), hyphen(-), period(.), colon(:), or an underscore(_).
    type: str
    aliases: [descr]
  tags:
    description:
      - List of tags in Key:<user-defined key> Value:<user-defined value> format.
    type: list
    elements: dict
  certificates:
    description:
      - List of certificates to manage in the policy.
      - Can include Root CA certificates and IMC certificates.
      - Only one IMC certificate can be configured per policy.
    type: list
    elements: dict
    suboptions:
      certificate_type:
        description:
          - Type of certificate to configure.
          - C(rootca) for Root CA certificates.
          - C(imc) for IMC certificates (only one allowed per policy).
        type: str
        choices: [rootca, imc]
        required: true
      certificate_name:
        description:
          - A name that helps identify a certificate.
          - Can be any string that adheres to the following constraints.
          - It should start and end with an alphanumeric character.
          - It can have underscores and hyphens.
          - It cannot be more than 30 characters.
          - Required for Root CA certificates.
        type: str
      certificate:
        description:
          - The PEM-encoded certificate data.
          - Must be base64 encoded.
          - Required for all certificate types.
        type: str
        required: true
      private_key:
        description:
          - The PEM-encoded private key for the certificate.
          - Must be base64 encoded.
          - Required only for IMC certificate type.
        type: str
      enabled:
        description:
          - Whether the certificate is enabled.
        type: bool
        default: true
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
- name: Create Certificate Management Policy with Root CA certificate
  cisco.intersight.intersight_certificate_management_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "CertMgmt-Policy-01"
    description: "Certificate management policy with Root CA"
    certificates:
      - certificate_type: rootca
        certificate_name: "RootCA-01"
        certificate: "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t..."
        enabled: true
    state: present

- name: Create Certificate Management Policy with IMC certificate
  cisco.intersight.intersight_certificate_management_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "CertMgmt-Policy-02"
    description: "Certificate management policy with IMC certificate"
    certificates:
      - certificate_type: imc
        certificate: "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t..."
        private_key: "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQ..."
        enabled: true
    state: present

- name: Create Certificate Management Policy with both types
  cisco.intersight.intersight_certificate_management_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "CertMgmt-Policy-03"
    description: "Certificate management policy with both certificate types"
    certificates:
      - certificate_type: rootca
        certificate_name: "RootCA-01"
        certificate: "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t..."
        enabled: true
      - certificate_type: imc
        certificate: "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t..."
        private_key: "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQ..."
        enabled: true
    state: present

- name: Update policy - remove all certificates
  cisco.intersight.intersight_certificate_management_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "CertMgmt-Policy-01"
    certificates: []
    state: present

- name: Delete Certificate Management Policy
  cisco.intersight.intersight_certificate_management_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "CertMgmt-Policy-01"
    state: absent
'''

RETURN = r'''
api_response:
  description: The API response output returned by the specified resource.
  returned: always
  type: dict
  sample:
    "api_response": {
        "Name": "CertMgmt-Policy-01",
        "ObjectType": "certificatemanagement.Policy",
        "Moid": "1234567890abcdef12345678",
        "Description": "Certificate management policy",
        "Certificates": [
            {
                "Certificate": {
                    "PemCertificate": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t..."
                },
                "CertificateName": "RootCA-01",
                "ObjectType": "certificatemanagement.RootCaCertificate",
                "Enabled": true
            }
        ],
        "Tags": [
            {
                "Key": "Environment",
                "Value": "Production"
            }
        ]
    }
'''


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.intersight.plugins.module_utils.intersight import IntersightModule, intersight_argument_spec
import re


def validate_certificate_name(certificate_name):
    """
    Validate certificate name according to Intersight constraints.
    """
    if not certificate_name:
        return False, "Certificate name is required for Root CA certificates"

    if len(certificate_name) > 30:
        return False, "Certificate name cannot be more than 30 characters"

    # Check if it starts and ends with alphanumeric
    if not re.match(r'^[a-zA-Z0-9].*[a-zA-Z0-9]$', certificate_name):
        return False, "Certificate name must start and end with an alphanumeric character"

    # Check if it only contains allowed characters (alphanumeric, underscore, hyphen)
    if not re.match(r'^[a-zA-Z0-9_-]+$', certificate_name):
        return False, "Certificate name can only contain alphanumeric characters, underscores, and hyphens"

    return True, ""


def build_certificate_object(cert_config):
    """
    Build certificate object for the Certificates array in policy API body.
    """
    cert_type = cert_config['certificate_type']

    cert_obj = {
        'Enabled': cert_config.get('enabled', True)
    }

    if cert_type == 'rootca':
        cert_obj['ObjectType'] = 'certificatemanagement.RootCaCertificate'
        cert_obj['CertificateName'] = cert_config['certificate_name']
    elif cert_type == 'imc':
        cert_obj['ObjectType'] = 'certificatemanagement.Imc'
        if cert_config.get('private_key'):
            cert_obj['Privatekey'] = cert_config['private_key']
            cert_obj['IsPrivatekeySet'] = True

    # Add certificate data
    if cert_config.get('certificate'):
        cert_obj['Certificate'] = {
            'PemCertificate': cert_config['certificate']
        }

    return cert_obj


def main():
    certificate_options = dict(
        certificate_type=dict(type='str', choices=['rootca', 'imc'], required=True),
        certificate_name=dict(type='str'),
        certificate=dict(type='str', required=True),
        private_key=dict(type='str', no_log=True),
        enabled=dict(type='bool', default=True)
    )

    argument_spec = intersight_argument_spec.copy()
    argument_spec.update(
        state=dict(type='str', choices=['present', 'absent'], default='present'),
        organization=dict(type='str', default='default'),
        name=dict(type='str', required=True),
        description=dict(type='str', aliases=['descr']),
        tags=dict(type='list', elements='dict'),
        certificates=dict(type='list', elements='dict', options=certificate_options)
    )

    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True
    )

    intersight = IntersightModule(module)
    intersight.result['api_response'] = {}
    intersight.result['trace_id'] = ''

    # Resource path used to configure policy
    resource_path = '/certificatemanagement/Policies'

    # Validate certificates configuration
    certificates = module.params.get('certificates') or []
    imc_count = 0

    for cert_config in certificates:
        cert_type = cert_config['certificate_type']

        # Count IMC certificates
        if cert_type == 'imc':
            imc_count += 1

        # Validate Root CA certificate name
        if cert_type == 'rootca':
            if not cert_config.get('certificate_name'):
                module.fail_json(msg="certificate_name is required for Root CA certificates")

            is_valid, error_msg = validate_certificate_name(cert_config['certificate_name'])
            if not is_valid:
                module.fail_json(msg=f"Invalid certificate name: {error_msg}")

        # Validate IMC certificate requirements
        if cert_type == 'imc':
            if not cert_config.get('private_key'):
                module.fail_json(msg="private_key is required for IMC certificates")

    # Validate only one IMC certificate per policy
    if imc_count > 1:
        module.fail_json(msg="Only one IMC certificate can be configured per policy")

    # Define API body used in compares or create
    intersight.api_body = {
        'Organization': {
            'Name': intersight.module.params['organization'],
        },
        'Name': intersight.module.params['name'],
    }

    if intersight.module.params['state'] == 'present':
        intersight.set_tags_and_description()

        # Build Certificates array
        if certificates:
            certificates_array = []
            for cert_config in certificates:
                cert_obj = build_certificate_object(cert_config)
                certificates_array.append(cert_obj)
            intersight.api_body['Certificates'] = certificates_array
        else:
            # Empty array to clear all certificates
            intersight.api_body['Certificates'] = []

    # Configure the policy
    intersight.configure_policy_or_profile(resource_path=resource_path)

    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
