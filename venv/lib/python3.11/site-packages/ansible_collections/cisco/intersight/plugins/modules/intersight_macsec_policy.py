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
module: intersight_macsec_policy
short_description: MACsec Policy configuration for Cisco Intersight
description:
  - Manages MACsec Policy configuration on Cisco Intersight.
  - A policy to configure MACsec encryption settings for fabric interconnect ports.
  - Supports primary keychain and optional fallback keychain configuration.
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
      - The name assigned to the MACsec Policy.
      - The name must be between 1 and 62 alphanumeric characters, allowing special characters :-_.
    type: str
    required: true
  description:
    description:
      - The user-defined description for the MACsec Policy.
      - Description can contain letters(a-z, A-Z), numbers(0-9), hyphen(-), period(.), colon(:), or an underscore(_).
    type: str
    aliases: [descr]
  tags:
    description:
      - List of tags in Key:<user-defined key> Value:<user-defined value> format.
    type: list
    elements: dict
  cipher_suite:
    description:
      - Cipher suite to be used for MACsec encryption.
    type: str
    choices: ['gcm-aes-xpn-256', 'gcm-aes-128', 'gcm-aes-256', 'gcm-aes-xpn-128']
    default: 'gcm-aes-xpn-256'
  confidentiality_offset:
    description:
      - The MACsec confidentiality offset specifies the number of bytes starting from the frame header.
      - MACsec encrypts only the bytes after the offset in a frame.
    type: str
    choices: ['conf-offset-0', 'conf-offset-30', 'conf-offset-50']
    default: 'conf-offset-0'
  security_policy:
    description:
      - The security policy specifies the level of MACsec enforcement on network traffic.
      - C(should-secure) allows unencrypted traffic until MKA session is secured.
      - C(must-secure) only allows MACsec encrypted traffic.
    type: str
    choices: ['should-secure', 'must-secure']
    default: 'should-secure'
  key_server_priority:
    description:
      - Key server is selected by comparing priority values during MKA message exchange.
      - Valid values range from 0 to 255.
      - Lower value means higher chance of being selected as key server.
    type: int
    default: 16
  sak_expiry_time:
    description:
      - Time in seconds to force secure association key (SAK) rekey.
      - Valid range is from 60 to 2592000 seconds.
      - When set to 0 or not configured, SAK rekey interval is determined based on interface speed.
    type: int
  replay_window_size:
    description:
      - Defines the size of the replay protection window.
      - Determines the number of packets that can be received out of order without being considered replay attacks.
      - Valid range is from 0 to 596000000.
    type: int
    default: 148809600
  include_icv_indicator:
    description:
      - Configures inclusion of the optional integrity check value (ICV) indicator.
      - Part of the transmitted MACsec key agreement protocol data unit (PDU).
    type: bool
    default: false
  eapol_mac_address:
    description:
      - MAC address to use in extensible authentication protocol over LAN (EAPoL) for MKA PDUs.
      - EAPol MAC address should not be equal to all-zero (0000.0000.0000).
    type: str
    default: '0180.C200.0003'
  eapol_ethertype:
    description:
      - Ethertype to use in EAPoL frames for MKA PDUs.
      - The range is between 0x600 - 0xffff.
    type: str
    default: '0x888e'
  primary_keychain_name:
    description:
      - Primary keychain name for managing the default set of security keys.
    type: str
  primary_keys:
    description:
      - List of security keys for the primary keychain.
    type: list
    elements: dict
    default: []
    suboptions:
      id:
        description:
          - Key ID must have an even number of hexadecimal characters (0-9, A-F).
          - Length must be between 2 and 64 characters.
        type: str
        required: true
      cryptographic_algorithm:
        description:
          - Cryptographic algorithm for the key.
        type: str
        choices: ['aes-256-cmac', 'aes-128-cmac']
        default: 'aes-256-cmac'
      secret:
        description:
          - Key secret is a shared secret used in cryptographic operations.
          - Must start with the character 'J'.
        type: str
        required: true
      key_lifetime_always_active:
        description:
          - Indicates that the key remains active indefinitely.
          - When C(true), the key is always active.
          - When C(false), C(start_time) and C(lifetime_type) must be specified.
        type: bool
        default: true
      timezone:
        description:
          - The time zone used for key lifetime configurations.
          - Only used when C(key_lifetime_always_active) is C(false).
        type: str
        choices: ['utc', 'local']
        default: 'utc'
      start_time:
        description:
          - The time of day and date when the key becomes active.
          - Format should be ISO 8601 format (e.g., 2025-11-20T09:14:00.000Z or 2025-11-20T09:14:00.000).
          - The 'Z' suffix will be automatically added if not provided.
          - Required when C(key_lifetime_always_active) is C(false).
        type: str
      lifetime_type:
        description:
          - Indicates key lifetime behavior after start time.
          - C(never) means the key remains active indefinitely after start time.
          - C(on-this-day) means the key becomes inactive at C(end_time).
        type: str
        choices: ['never', 'on-this-day']
        default: 'never'
      end_time:
        description:
          - The time of day and date when the key becomes inactive.
          - Format should be ISO 8601 format (e.g., 2025-11-21T09:20:00.000Z or 2025-11-21T09:20:00.000).
          - The 'Z' suffix will be automatically added if not provided.
          - Required when C(lifetime_type) is C(on-this-day).
        type: str
  configure_fallback_keychain:
    description:
      - Enable configuration of fallback keychain.
    type: bool
    default: false
  fallback_keychain_name:
    description:
      - Fallback keychain name.
      - Required when C(configure_fallback_keychain) is C(true).
    type: str
  fallback_keys:
    description:
      - List of security keys for the fallback keychain.
    type: list
    elements: dict
    default: []
    suboptions:
      id:
        description:
          - Key ID must have an even number of hexadecimal characters (0-9, A-F).
          - Length must be between 2 and 64 characters.
        type: str
        required: true
      cryptographic_algorithm:
        description:
          - Cryptographic algorithm for the key.
        type: str
        choices: ['aes-256-cmac', 'aes-128-cmac']
        default: 'aes-256-cmac'
      secret:
        description:
          - Key secret is a shared secret used in cryptographic operations.
          - Must start with the character 'J'.
        type: str
        required: true
      key_lifetime_always_active:
        description:
          - Indicates that the key remains active indefinitely.
          - When C(true), the key is always active.
          - When C(false), C(start_time) and C(lifetime_type) must be specified.
        type: bool
        default: true
      timezone:
        description:
          - The time zone used for key lifetime configurations.
          - Only used when C(key_lifetime_always_active) is C(false).
        type: str
        choices: ['utc', 'local']
        default: 'utc'
      start_time:
        description:
          - The time of day and date when the key becomes active.
          - Format should be ISO 8601 format (e.g., 2025-11-20T09:14:00.000Z or 2025-11-20T09:14:00.000).
          - The 'Z' suffix will be automatically added if not provided.
          - Required when C(key_lifetime_always_active) is C(false).
        type: str
      lifetime_type:
        description:
          - Indicates key lifetime behavior after start time.
          - C(never) means the key remains active indefinitely after start time.
          - C(on-this-day) means the key becomes inactive at C(end_time).
        type: str
        choices: ['never', 'on-this-day']
        default: 'never'
      end_time:
        description:
          - The time of day and date when the key becomes inactive.
          - Format should be ISO 8601 format (e.g., 2025-11-21T09:20:00.000Z or 2025-11-21T09:20:00.000).
          - The 'Z' suffix will be automatically added if not provided.
          - Required when C(lifetime_type) is C(on-this-day).
        type: str
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
- name: Create MACsec Policy with Primary Keychain Only
  cisco.intersight.intersight_macsec_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "macsec-policy-01"
    description: "MACsec policy with primary keychain"
    cipher_suite: "gcm-aes-xpn-256"
    security_policy: "should-secure"
    primary_keychain_name: "primary-keychain"
    primary_keys:
      - id: "1234"
        cryptographic_algorithm: "aes-256-cmac"
        secret: >-
          Ja1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9bd2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c122222222222222222222222222222222222222222222
        key_lifetime_always_active: true
    tags:
      - Key: Environment
        Value: Production
    state: present

- name: Create MACsec Policy with Fallback Keychain
  cisco.intersight.intersight_macsec_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "macsec-policy-02"
    description: "MACsec policy with fallback keychain"
    cipher_suite: "gcm-aes-256"
    security_policy: "must-secure"
    key_server_priority: 32
    sak_expiry_time: 3600
    primary_keychain_name: "primary-keychain"
    primary_keys:
      - id: "ABCD"
        cryptographic_algorithm: "aes-256-cmac"
        secret: >-
          Ja1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9bd2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c122222222222222222222222222222222222222222222
    configure_fallback_keychain: true
    fallback_keychain_name: "fallback-keychain"
    fallback_keys:
      - id: "EF12"
        cryptographic_algorithm: "aes-128-cmac"
        secret: "Jf1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6b7a8f9e0d1c2b3a4f5e6d7c8b9a0f1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6b7a8f9e0d1c2b3a4f5e6d7c8b9a0f1e2d3c4b5a6f7e8d9c0"
    state: present

- name: Create MACsec Policy with Custom Settings
  cisco.intersight.intersight_macsec_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "macsec-policy-custom"
    description: "MACsec policy with custom settings"
    cipher_suite: "gcm-aes-xpn-128"
    confidentiality_offset: "conf-offset-30"
    security_policy: "must-secure"
    key_server_priority: 64
    sak_expiry_time: 7200
    replay_window_size: 200000000
    include_icv_indicator: true
    eapol_mac_address: "0180.C200.0004"
    eapol_ethertype: "0x88e5"
    primary_keychain_name: "custom-keychain"
    primary_keys:
      - id: "2468"
        cryptographic_algorithm: "aes-256-cmac"
        secret: "Jabcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz"
    state: present

- name: Create MACsec Policy with Scheduled Key Lifetime (Never Expires)
  cisco.intersight.intersight_macsec_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "macsec-policy-scheduled-never"
    description: "MACsec policy with scheduled key that never expires"
    primary_keychain_name: "scheduled-keychain"
    primary_keys:
      - id: "3456"
        cryptographic_algorithm: "aes-256-cmac"
        secret: "Jabcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz"
        key_lifetime_always_active: false
        timezone: "local"
        start_time: "2025-11-20T10:00:00.000"
        lifetime_type: "never"
    state: present

- name: Create MACsec Policy with Scheduled Key Lifetime (With End Time)
  cisco.intersight.intersight_macsec_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "macsec-policy-scheduled-endtime"
    description: "MACsec policy with scheduled key with end time"
    primary_keychain_name: "scheduled-keychain-endtime"
    primary_keys:
      - id: "4567"
        cryptographic_algorithm: "aes-256-cmac"
        secret: "Jabcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz"
        key_lifetime_always_active: false
        timezone: "utc"
        start_time: "2025-11-20T09:20:00.000Z"
        lifetime_type: "on-this-day"
        end_time: "2025-11-21T09:20:00.000Z"
    state: present

- name: Delete MACsec Policy
  cisco.intersight.intersight_macsec_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "macsec-policy-01"
    state: absent
'''

RETURN = r'''
api_response:
  description: The API response output returned by the specified resource.
  returned: always
  type: dict
  sample:
    "api_response": {
        "Name": "macsec-policy-01",
        "ObjectType": "fabric.MacsecPolicy",
        "Description": "MACsec policy with primary keychain",
        "CipherSuite": "GCM-AES-XPN-256",
        "ConfidentialityOffset": "CONF-OFFSET-0",
        "SecurityPolicy": "Should-secure",
        "KeyServerPriority": 16,
        "SakExpiryTime": 0,
        "ReplayWindowSize": 148809600,
        "IncludeIcvIndicator": false,
        "MacSecEaPol": {
            "EaPolMacAddress": "0180.C200.0003",
            "EaPolEthertype": "0x888e"
        },
        "PrimaryKeyChain": {
            "Name": "primary-keychain",
            "SecKeys": [
                {
                    "Id": "1234",
                    "CryptographicAlgorithm": "AES_256_CMAC",
                    "KeyType": "Type-6",
                    "SendLifetimeUnlimited": true,
                    "SendLifetimeInfinite": false,
                    "IsOctetStringSet": true
                }
            ]
        },
        "FallbackKeyChain": {
            "Name": "",
            "SecKeys": null
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


def validate_key_id(key_id, field_name):
    """
    Validate key ID format.
    """
    if not key_id:
        return False, f"{field_name} is required"
    if len(key_id) < 2 or len(key_id) > 64:
        return False, f"{field_name} must be between 2 and 64 characters"
    if len(key_id) % 2 != 0:
        return False, f"{field_name} must have an even number of characters"
    if not all(c in '0123456789ABCDEFabcdef' for c in key_id):
        return False, f"{field_name} must contain only hexadecimal characters (0-9, A-F)"
    return True, None


def validate_secret(secret, field_name):
    """
    Validate secret format.
    """
    if not secret:
        return False, f"{field_name} is required"
    if not secret.startswith('J'):
        return False, f"{field_name} must start with the character 'J'"
    return True, None


def validate_macsec_configuration(module):
    """
    Validate MACsec Policy configuration parameters.
    """
    params = module.params
    if params['state'] == 'present':
        if not params.get('primary_keychain_name'):
            module.fail_json(msg="primary_keychain_name is required when state is present")

        if params.get('key_server_priority') is not None:
            if params['key_server_priority'] < 0 or params['key_server_priority'] > 255:
                module.fail_json(msg="key_server_priority must be between 0 and 255")

        if params.get('sak_expiry_time') is not None and params['sak_expiry_time'] != 0:
            if params['sak_expiry_time'] < 60 or params['sak_expiry_time'] > 2592000:
                module.fail_json(msg="sak_expiry_time must be between 60 and 2592000 seconds, or 0 for auto-determination")

        if params.get('replay_window_size') is not None:
            if params['replay_window_size'] < 0 or params['replay_window_size'] > 596000000:
                module.fail_json(msg="replay_window_size must be between 0 and 596000000")

        if params.get('eapol_mac_address'):
            if params['eapol_mac_address'].replace('.', '').lower() == '000000000000':
                module.fail_json(msg="eapol_mac_address cannot be all zeros (0000.0000.0000)")

        for key in params.get('primary_keys', []):
            is_valid, error_msg = validate_key_id(key.get('id'), 'primary_keys.id')
            if not is_valid:
                module.fail_json(msg=error_msg)
            is_valid, error_msg = validate_secret(key.get('secret'), 'primary_keys.secret')
            if not is_valid:
                module.fail_json(msg=error_msg)
                if not key.get('key_lifetime_always_active', True):
                    if not key.get('start_time'):
                        module.fail_json(msg="primary_keys.start_time is required when key_lifetime_always_active is false")
                    if key.get('lifetime_type') == 'on-this-day' and not key.get('end_time'):
                        module.fail_json(msg="primary_keys.end_time is required when lifetime_type is 'on-this-day'")

        if params.get('configure_fallback_keychain'):
            if not params.get('fallback_keychain_name'):
                module.fail_json(msg="fallback_keychain_name is required when configure_fallback_keychain is true")
            for key in params.get('fallback_keys', []):
                is_valid, error_msg = validate_key_id(key.get('id'), 'fallback_keys.id')
                if not is_valid:
                    module.fail_json(msg=error_msg)
                is_valid, error_msg = validate_secret(key.get('secret'), 'fallback_keys.secret')
                if not is_valid:
                    module.fail_json(msg=error_msg)
                if not key.get('key_lifetime_always_active', True):
                    if not key.get('start_time'):
                        module.fail_json(msg="fallback_keys.start_time is required when key_lifetime_always_active is false")
                    if key.get('lifetime_type') == 'on-this-day' and not key.get('end_time'):
                        module.fail_json(msg="fallback_keys.end_time is required when lifetime_type is 'on-this-day'")


def build_keychain_config(keychain_name, keys):
    """
    Build keychain configuration for API body.
    """
    keychain_config = {
        'Name': keychain_name
    }
    if keys:
        sec_keys = []
        for key in keys:
            sec_key = {
                'Id': key['id'],
                'CryptographicAlgorithm': convert_to_api_format(key.get('cryptographic_algorithm', 'aes-256-cmac'), 'cryptographic_algorithm'),
                'KeyType': 'Type-6',
                'OctetString': key['secret'],
                'SendLifetimeUnlimited': key.get('key_lifetime_always_active', True),
                'IsOctetStringSet': True
            }
            if not key.get('key_lifetime_always_active', True):
                timezone = key.get('timezone', 'utc')
                sec_key['SendLifetimeTimeZone'] = 'UTC' if timezone == 'utc' else 'Local'
                start_time = key['start_time']
                if not start_time.endswith('Z'):
                    start_time = start_time + 'Z'
                sec_key['SendLifetimeStartTime'] = start_time
                if key.get('lifetime_type', 'never') == 'never':
                    sec_key['SendLifetimeInfinite'] = True
                else:
                    sec_key['SendLifetimeInfinite'] = False
                    end_time = key['end_time']
                    if not end_time.endswith('Z'):
                        end_time = end_time + 'Z'
                    sec_key['SendLifetimeEndTime'] = end_time
            else:
                sec_key['SendLifetimeInfinite'] = False
            sec_keys.append(sec_key)
        keychain_config['SecKeys'] = sec_keys
    return keychain_config


def convert_to_api_format(value, value_type):
    """
    Convert lowercase user-facing values to API format.
    """
    if value_type == 'cipher_suite':
        return value.upper()
    elif value_type == 'confidentiality_offset':
        return value.upper()
    elif value_type == 'security_policy':
        parts = value.split('-')
        return f"{parts[0].capitalize()}-{parts[1]}"
    elif value_type == 'cryptographic_algorithm':
        return value.upper().replace('-', '_')
    return value


def build_api_body(intersight):
    """
    Build the API body for MACsec Policy configuration.
    """
    params = intersight.module.params
    intersight.api_body = {
        'Organization': {
            'Name': params['organization'],
        },
        'Name': params['name']
    }
    if params['state'] == 'present':
        intersight.set_tags_and_description()
        intersight.api_body['CipherSuite'] = convert_to_api_format(params['cipher_suite'], 'cipher_suite')
        intersight.api_body['ConfidentialityOffset'] = convert_to_api_format(params['confidentiality_offset'], 'confidentiality_offset')
        intersight.api_body['SecurityPolicy'] = convert_to_api_format(params['security_policy'], 'security_policy')
        intersight.api_body['KeyServerPriority'] = params['key_server_priority']
        intersight.api_body['ReplayWindowSize'] = params['replay_window_size']
        intersight.api_body['IncludeIcvIndicator'] = params['include_icv_indicator']
        if params.get('sak_expiry_time') is not None:
            intersight.api_body['SakExpiryTime'] = params['sak_expiry_time']

        intersight.api_body['MacSecEaPol'] = {
            'EaPolMacAddress': params['eapol_mac_address'],
            'EaPolEthertype': params['eapol_ethertype']
        }

        intersight.api_body['PrimaryKeyChain'] = build_keychain_config(
            params['primary_keychain_name'],
            params.get('primary_keys', [])
        )
        if params.get('configure_fallback_keychain') and params.get('fallback_keychain_name'):
            intersight.api_body['FallbackKeyChain'] = build_keychain_config(
                params['fallback_keychain_name'],
                params.get('fallback_keys', [])
            )
        else:
            intersight.api_body['FallbackKeyChain'] = {
                'Name': '',
                'SecKeys': None
            }


def main():
    argument_spec = intersight_argument_spec.copy()
    argument_spec.update(
        state=dict(type='str', choices=['present', 'absent'], default='present'),
        organization=dict(type='str', default='default'),
        name=dict(type='str', required=True),
        description=dict(type='str', aliases=['descr']),
        tags=dict(type='list', elements='dict'),
        cipher_suite=dict(type='str', choices=['gcm-aes-xpn-256', 'gcm-aes-128', 'gcm-aes-256', 'gcm-aes-xpn-128'], default='gcm-aes-xpn-256'),
        confidentiality_offset=dict(type='str', choices=['conf-offset-0', 'conf-offset-30', 'conf-offset-50'], default='conf-offset-0'),
        security_policy=dict(type='str', choices=['should-secure', 'must-secure'], default='should-secure'),
        key_server_priority=dict(type='int', default=16),
        sak_expiry_time=dict(type='int'),
        replay_window_size=dict(type='int', default=148809600),
        include_icv_indicator=dict(type='bool', default=False),
        eapol_mac_address=dict(type='str', default='0180.C200.0003'),
        eapol_ethertype=dict(type='str', default='0x888e'),
        primary_keychain_name=dict(type='str'),
        primary_keys=dict(
            type='list',
            elements='dict',
            default=[],
            no_log=True,
            options=dict(
                id=dict(type='str', required=True),
                cryptographic_algorithm=dict(type='str', choices=['aes-256-cmac', 'aes-128-cmac'], default='aes-256-cmac'),
                secret=dict(type='str', required=True, no_log=True),
                key_lifetime_always_active=dict(type='bool', default=True),
                timezone=dict(type='str', choices=['utc', 'local'], default='utc'),
                start_time=dict(type='str'),
                lifetime_type=dict(type='str', choices=['never', 'on-this-day'], default='never'),
                end_time=dict(type='str')
            )
        ),
        configure_fallback_keychain=dict(type='bool', default=False),
        fallback_keychain_name=dict(type='str'),
        fallback_keys=dict(
            type='list',
            elements='dict',
            default=[],
            no_log=True,
            options=dict(
                id=dict(type='str', required=True),
                cryptographic_algorithm=dict(type='str', choices=['aes-256-cmac', 'aes-128-cmac'], default='aes-256-cmac'),
                secret=dict(type='str', required=True, no_log=True),
                key_lifetime_always_active=dict(type='bool', default=True),
                timezone=dict(type='str', choices=['utc', 'local'], default='utc'),
                start_time=dict(type='str'),
                lifetime_type=dict(type='str', choices=['never', 'on-this-day'], default='never'),
                end_time=dict(type='str')
            )
        )
    )
    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True,
    )
    if module.params['state'] == 'present':
        validate_macsec_configuration(module)

    intersight = IntersightModule(module)
    intersight.result['api_response'] = {}
    intersight.result['trace_id'] = ''

    build_api_body(intersight)

    resource_path = '/fabric/MacSecPolicies'
    intersight.configure_policy_or_profile(resource_path=resource_path)

    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
