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
module: intersight_drive_security_policy
short_description: Drive Security Policy configuration for Cisco Intersight
description:
  - Manages Drive Security Policy configuration on Cisco Intersight.
  - A policy to configure drive security settings for Cisco Intersight managed servers.
  - Supports both Manual key management and Remote key management (KMIP).
  - For more information see L(Cisco Intersight,https://intersight.com/apidocs).
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
      - Profiles, Policies, and Pools that are created within a Custom Organization are applicable only to devices in the same Organization.
    type: str
    default: default
  name:
    description:
      - The name assigned to the Drive Security Policy.
      - The name must be between 1 and 62 alphanumeric characters, allowing special characters :-_.
    type: str
    required: true
  description:
    description:
      - The user-defined description for the Drive Security Policy.
      - Description can contain letters(a-z, A-Z), numbers(0-9), hyphen(-), period(.), colon(:), or an underscore(_).
    type: str
    aliases: [descr]
  tags:
    description:
      - List of tags in Key:<user-defined key> Value:<user-defined value> format.
    type: list
    elements: dict
    default: []
  manual_key:
    description:
      - Configuration for manual key management.
      - Use this for local key management with manual passphrase.
      - Either C(manual_key) or C(remote_key) must be specified, but not both.
    type: dict
    suboptions:
      new_key:
        description:
          - New Security Key Passphrase to be configured on the server.
          - The passphrase must be at least 8 characters long and include at least one uppercase letter, one lowercase letter, one number, and one
            special character.
        type: str
        required: true
      existing_key:
        description:
          - Current Security Key Passphrase which is already configured on the server.
          - Required only if drive security is already enabled with manual key.
          - The passphrase must be at least 8 characters long and include at least one uppercase letter, one lowercase letter, one number, and one
            special character.
        type: str
  remote_key:
    description:
      - Configuration for remote key management using KMIP server.
      - Use this for remote key management with KMIP protocol.
      - Either C(manual_key) or C(remote_key) must be specified, but not both.
    type: dict
    suboptions:
      primary_server:
        description:
          - Primary KMIP server configuration.
          - At least one of C(primary_server) or C(secondary_server) must be enabled.
        type: dict
        suboptions:
          enable_drive_security:
            description:
              - Enables/disables the primary KMIP server.
            type: bool
            required: true
          ip_address:
            description:
              - The IP address or hostname of the KMIP server.
              - Can be an IPv4 address, IPv6 address, or hostname.
              - Hostnames are valid only when Inband is configured for the CIMC address.
              - Required when C(enable_drive_security) is C(true).
            type: str
          port:
            description:
              - The port to which the KMIP client should connect.
              - Valid range is 1024-65535.
            type: int
            default: 5696
          timeout:
            description:
              - The timeout before which the KMIP client should connect.
              - Valid range is 1-250 seconds.
            type: int
            default: 60
      secondary_server:
        description:
          - Secondary KMIP server configuration.
          - At least one of C(primary_server) or C(secondary_server) must be enabled.
        type: dict
        suboptions:
          enable_drive_security:
            description:
              - Enables/disables the secondary KMIP server.
            type: bool
            required: true
          ip_address:
            description:
              - The IP address or hostname of the KMIP server.
              - Can be an IPv4 address, IPv6 address, or hostname.
              - Hostnames are valid only when Inband is configured for the CIMC address.
              - Required when C(enable_drive_security) is C(true).
            type: str
          port:
            description:
              - The port to which the KMIP client should connect.
              - Valid range is 1024-65535.
            type: int
            default: 5696
          timeout:
            description:
              - The timeout before which the KMIP client should connect.
              - Valid range is 1-250 seconds.
            type: int
            default: 60
      server_certificate:
        description:
          - Server Public Root CA Certificate in base64 encoded format.
          - Required when using remote key management (KMIP).
        type: str
        required: true
      use_authentication:
        description:
          - Enables/disables authentication for communicating with KMIP server.
          - When enabled, authentication is mandatory.
        type: bool
        default: false
      username:
        description:
          - The username for the KMIP server login.
          - Required when C(use_authentication) is C(true).
        type: str
      password:
        description:
          - The password for the KMIP server login.
          - Optional parameter for KMIP authentication.
        type: str
      existing_key:
        description:
          - Current Security Key Passphrase which is already configured on the server.
          - Required only if drive security is already enabled with manual key and switching to KMIP.
          - The passphrase must be at least 8 characters long and include at least one uppercase letter, one lowercase letter, one number, and one
            special character.
        type: str
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
- name: Create Drive Security Policy with Manual Key
  cisco.intersight.intersight_drive_security_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "manual-drive-security-policy"
    description: "Drive security policy with manual key management"
    manual_key:
      new_key: "MyS3cur3P@ssw0rd"
    tags:
      - Key: "Environment"
        Value: "Production"
    state: present

- name: Create Drive Security Policy with Manual Key (updating existing)
  cisco.intersight.intersight_drive_security_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "manual-drive-security-policy"
    description: "Drive security policy with manual key management"
    manual_key:
      new_key: "MyN3wS3cur3P@ssw0rd"
      existing_key: "MyS3cur3P@ssw0rd"
    state: present

- name: Create Drive Security Policy with KMIP (Primary Server Only)
  cisco.intersight.intersight_drive_security_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "kmip-drive-security-policy"
    description: "Drive security policy with KMIP"
    remote_key:
      primary_server:
        enable_drive_security: true
        ip_address: "192.168.1.100"
        port: 5696
        timeout: 60
      secondary_server:
        enable_drive_security: false
      server_certificate: "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t..."
      use_authentication: false
    state: present

- name: Create Drive Security Policy with KMIP (Both Servers with Authentication)
  cisco.intersight.intersight_drive_security_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "kmip-auth-drive-security-policy"
    description: "Drive security policy with KMIP and authentication"
    remote_key:
      primary_server:
        enable_drive_security: true
        ip_address: "192.168.1.100"
        port: 5696
        timeout: 60
      secondary_server:
        enable_drive_security: true
        ip_address: "192.168.1.101"
        port: 5696
        timeout: 60
      server_certificate: "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t..."
      use_authentication: true
      username: "kmip_user"
      password: "kmip_password"
    state: present

- name: Delete Drive Security Policy
  cisco.intersight.intersight_drive_security_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "manual-drive-security-policy"
    state: absent
'''

RETURN = r'''
api_response:
  description: The API response output returned by the specified resource.
  returned: always
  type: dict
  sample:
    "api_response": {
        "Name": "manual-drive-security-policy",
        "ObjectType": "storage.DriveSecurityPolicy",
        "Description": "Drive security policy with manual key management",
        "KeySetting": {
            "ClassId": "storage.KeySetting",
            "ObjectType": "storage.KeySetting",
            "KeyType": "Manual",
            "ManualKey": {
                "ClassId": "storage.LocalKeySetting",
                "ObjectType": "storage.LocalKeySetting",
                "IsExistingKeySet": false,
                "IsNewKeySet": true
            },
            "RemoteKey": {
                "ClassId": "storage.RemoteKeySetting",
                "ObjectType": "storage.RemoteKeySetting",
                "AuthCredentials": {
                    "ClassId": "storage.KmipAuthCredentials",
                    "ObjectType": "storage.KmipAuthCredentials",
                    "IsPasswordSet": false,
                    "UseAuthentication": false,
                    "Username": ""
                },
                "IsExistingKeySet": false,
                "PrimaryServer": {
                    "ClassId": "storage.KmipServer",
                    "ObjectType": "storage.KmipServer",
                    "EnableDriveSecurity": false,
                    "IpAddress": "",
                    "Port": 5696,
                    "Timeout": 60
                },
                "SecondaryServer": {
                    "ClassId": "storage.KmipServer",
                    "ObjectType": "storage.KmipServer",
                    "EnableDriveSecurity": false,
                    "IpAddress": "",
                    "Port": 5696,
                    "Timeout": 60
                },
                "ServerCertificate": ""
            }
        },
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


def validate_passphrase(passphrase, field_name):
    """
    Validate that a passphrase meets security requirements.
    """
    if not passphrase:
        return True, None
    if len(passphrase) < 8:
        return False, f"{field_name} must be at least 8 characters long"
    has_upper = any(c.isupper() for c in passphrase)
    has_lower = any(c.islower() for c in passphrase)
    has_digit = any(c.isdigit() for c in passphrase)
    has_special = any(not c.isalnum() for c in passphrase)
    if not (has_upper and has_lower and has_digit and has_special):
        return False, f"{field_name} must include at least one uppercase letter, one lowercase letter, one number, and one special character"
    return True, None


def validate_drive_security_configuration(module):
    """
    Validate Drive Security Policy configuration parameters.
    """
    params = module.params
    if params['state'] == 'present':
        manual_key = params.get('manual_key')
        remote_key = params.get('remote_key')
        if not manual_key and not remote_key:
            module.fail_json(msg="Either manual_key or remote_key must be specified")
        if manual_key and remote_key:
            module.fail_json(msg="Cannot specify both manual_key and remote_key - choose one key management type")
        if manual_key:
            if not manual_key.get('new_key'):
                module.fail_json(msg="manual_key.new_key is required when using manual key management")
            is_valid, error_msg = validate_passphrase(manual_key.get('new_key'), 'manual_key.new_key')
            if not is_valid:
                module.fail_json(msg=error_msg)
            if manual_key.get('existing_key'):
                is_valid, error_msg = validate_passphrase(manual_key.get('existing_key'), 'manual_key.existing_key')
                if not is_valid:
                    module.fail_json(msg=error_msg)
        elif remote_key:
            if not remote_key.get('server_certificate'):
                module.fail_json(msg="remote_key.server_certificate is required when using remote key management (KMIP)")
            primary_server = remote_key.get('primary_server', {})
            secondary_server = remote_key.get('secondary_server', {})
            primary_enabled = primary_server.get('enable_drive_security', False)
            secondary_enabled = secondary_server.get('enable_drive_security', False)
            if not primary_enabled and not secondary_enabled:
                module.fail_json(msg="At least one of primary_server or secondary_server must be enabled")
            if primary_enabled:
                if not primary_server.get('ip_address'):
                    module.fail_json(msg="primary_server.ip_address is required when primary_server is enabled")
                port = primary_server.get('port', 5696)
                if port < 1024 or port > 65535:
                    module.fail_json(msg="primary_server.port must be between 1024 and 65535")
                timeout = primary_server.get('timeout', 60)
                if timeout < 1 or timeout > 250:
                    module.fail_json(msg="primary_server.timeout must be between 1 and 250")
            if secondary_enabled:
                if not secondary_server.get('ip_address'):
                    module.fail_json(msg="secondary_server.ip_address is required when secondary_server is enabled")
                port = secondary_server.get('port', 5696)
                if port < 1024 or port > 65535:
                    module.fail_json(msg="secondary_server.port must be between 1024 and 65535")
                timeout = secondary_server.get('timeout', 60)
                if timeout < 1 or timeout > 250:
                    module.fail_json(msg="secondary_server.timeout must be between 1 and 250")
            if remote_key.get('use_authentication'):
                if not remote_key.get('username'):
                    module.fail_json(msg="remote_key.username is required when use_authentication is true")
            if remote_key.get('existing_key'):
                is_valid, error_msg = validate_passphrase(remote_key.get('existing_key'), 'remote_key.existing_key')
                if not is_valid:
                    module.fail_json(msg=error_msg)


def build_manual_key_config(manual_key):
    """
    Build ManualKey configuration for API body.
    """
    manual_key_config = {
        'NewKey': manual_key['new_key']
    }
    if manual_key.get('existing_key'):
        manual_key_config['ExistingKey'] = manual_key['existing_key']
    else:
        manual_key_config['ExistingKey'] = ''
    return manual_key_config


def build_remote_key_config(remote_key):
    """
    Build RemoteKey configuration for API body.
    """
    remote_key_config = {}
    auth_credentials = {
        'UseAuthentication': remote_key.get('use_authentication', False)
    }
    if remote_key.get('use_authentication'):
        auth_credentials['Username'] = remote_key['username']
        if remote_key.get('password'):
            auth_credentials['Password'] = remote_key['password']
    remote_key_config['AuthCredentials'] = auth_credentials
    remote_key_config['ServerCertificate'] = remote_key['server_certificate']
    primary_server = remote_key.get('primary_server', {})
    primary_server_config = {
        'EnableDriveSecurity': primary_server.get('enable_drive_security', False)
    }
    if primary_server.get('enable_drive_security'):
        primary_server_config['IpAddress'] = primary_server['ip_address']
        primary_server_config['Port'] = primary_server.get('port', 5696)
        primary_server_config['Timeout'] = primary_server.get('timeout', 60)
    else:
        primary_server_config['IpAddress'] = ''
        primary_server_config['Port'] = 5696
        primary_server_config['Timeout'] = 60
    remote_key_config['PrimaryServer'] = primary_server_config
    secondary_server = remote_key.get('secondary_server', {})
    secondary_server_config = {
        'EnableDriveSecurity': secondary_server.get('enable_drive_security', False)
    }
    if secondary_server.get('enable_drive_security'):
        secondary_server_config['IpAddress'] = secondary_server['ip_address']
        secondary_server_config['Port'] = secondary_server.get('port', 5696)
        secondary_server_config['Timeout'] = secondary_server.get('timeout', 60)
    else:
        secondary_server_config['IpAddress'] = ''
        secondary_server_config['Port'] = 5696
        secondary_server_config['Timeout'] = 60
    remote_key_config['SecondaryServer'] = secondary_server_config
    if remote_key.get('existing_key'):
        remote_key_config['ExistingKey'] = remote_key['existing_key']
    else:
        remote_key_config['ExistingKey'] = ''
    return remote_key_config


def build_api_body(intersight):
    """
    Build the API body for Drive Security Policy configuration.
    """
    params = intersight.module.params
    if params['state'] == 'present':
        intersight.api_body = {
            'Organization': {
                'Name': params['organization'],
            },
            'Name': params['name']
        }
        intersight.set_tags_and_description()
        key_setting = {}
        if params.get('manual_key'):
            key_setting['KeyType'] = 'Manual'
            key_setting['ManualKey'] = build_manual_key_config(params['manual_key'])
        elif params.get('remote_key'):
            key_setting['KeyType'] = 'Kmip'
            key_setting['RemoteKey'] = build_remote_key_config(params['remote_key'])
        intersight.api_body['KeySetting'] = key_setting


def main():
    argument_spec = intersight_argument_spec.copy()
    argument_spec.update(
        state=dict(type='str', choices=['present', 'absent'], default='present'),
        organization=dict(type='str', default='default'),
        name=dict(type='str', required=True),
        description=dict(type='str', aliases=['descr']),
        tags=dict(type='list', elements='dict', default=[]),
        manual_key=dict(
            type='dict',
            no_log=True,
            options=dict(
                new_key=dict(type='str', required=True, no_log=True),
                existing_key=dict(type='str', no_log=True)
            )
        ),
        remote_key=dict(
            type='dict',
            no_log=True,
            options=dict(
                primary_server=dict(
                    type='dict',
                    options=dict(
                        enable_drive_security=dict(type='bool', required=True),
                        ip_address=dict(type='str'),
                        port=dict(type='int', default=5696),
                        timeout=dict(type='int', default=60)
                    )
                ),
                secondary_server=dict(
                    type='dict',
                    options=dict(
                        enable_drive_security=dict(type='bool', required=True),
                        ip_address=dict(type='str'),
                        port=dict(type='int', default=5696),
                        timeout=dict(type='int', default=60)
                    )
                ),
                server_certificate=dict(type='str', required=True),
                use_authentication=dict(type='bool', default=False),
                username=dict(type='str'),
                password=dict(type='str', no_log=True),
                existing_key=dict(type='str', no_log=True)
            )
        )
    )
    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True,
    )
    if module.params['state'] == 'present':
        validate_drive_security_configuration(module)

    intersight = IntersightModule(module)
    intersight.result['api_response'] = {}
    intersight.result['trace_id'] = ''

    build_api_body(intersight)
    resource_path = '/storage/DriveSecurityPolicies'
    intersight.configure_policy_or_profile(resource_path=resource_path)

    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
