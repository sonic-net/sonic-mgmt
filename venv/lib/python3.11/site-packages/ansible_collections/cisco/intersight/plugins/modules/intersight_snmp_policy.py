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
module: intersight_snmp_policy
short_description: SNMP Policy configuration for Cisco Intersight
description:
  - Manages SNMP Policy configuration on Cisco Intersight.
  - A policy to configure SNMP settings for Cisco Intersight managed servers.
  - Supports both SNMPv2c and SNMPv3 configurations with users, traps, and community strings.
  - For more information see L(Cisco Intersight,https://intersight.com/apidocs/snmp/Policy/get/).
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
      - The name assigned to the SNMP Policy.
      - The name must be between 1 and 62 alphanumeric characters, allowing special characters :-_.
    type: str
    required: true
  description:
    description:
      - The user-defined description for the SNMP Policy.
      - Description can contain letters(a-z, A-Z), numbers(0-9), hyphen(-), period(.), colon(:), or an underscore(_).
    type: str
    aliases: [descr]
  tags:
    description:
      - List of tags in Key:<user-defined key> Value:<user-defined value> format.
    type: list
    elements: dict
  enabled:
    description:
      - State of the SNMP Policy on the endpoint.
      - If enabled, the endpoint sends SNMP traps to the designated host.
    type: bool
    default: true
  v2c_enabled:
    description:
      - State of the SNMPv2c protocol.
      - When enabled, SNMPv2c access is available for the associated servers.
    type: bool
    default: true
  v3_enabled:
    description:
      - State of the SNMPv3 protocol.
      - When enabled, SNMPv3 access is available for the associated servers.
    type: bool
    default: true
  snmp_port:
    description:
      - Port on which Cisco IMC SNMP agent runs. Enter a value between 1-65535.
      - Reserved ports not allowed (22, 23, 80, 123, 389, 443, 623, 636, 2068, 3268, 3269).
    type: int
    default: 161
  sys_contact:
    description:
      - Contact person responsible for the SNMP implementation.
      - Enter a string up to 64 characters, such as an email address or a name and telephone number.
      - Required when C(enabled) is C(true).
    type: str
  sys_location:
    description:
      - Location of the host on which the SNMP agent (server) runs.
      - Required when C(enabled) is C(true).
    type: str
  community_access:
    description:
      - Controls access to the information in the inventory tables.
      - Applicable only for SNMPv2c users.
      - For SNMPv3, this is always set to C(Disabled).
      - For SNMPv2c, valid choices are C(Disabled), C(Limited), and C(Full).
      - Required when C(enabled) is C(true).
    type: str
    choices: [Disabled, Limited, Full]
    default: Disabled
  access_community_string:
    description:
      - The default SNMPv1, SNMPv2c community name or SNMPv3 username to include on any trap messages sent to the SNMP host.
      - The name can be 32 characters long.
      - Used with SNMPv2c access only.
    type: str
  trap_community:
    description:
      - SNMP community group used for sending SNMP trap to other devices.
      - Valid only for SNMPv2c users.
    type: str
  engine_input_id:
    description:
      - User-defined unique identification of the static engine.
      - Used with SNMPv3 only.
    type: str
  snmp_users:
    description:
      - List of SNMP users for SNMPv3 authentication.
    type: list
    elements: dict
    suboptions:
      name:
        description:
          - SNMP username.
          - Must have a minimum of 1 and and a maximum of 31 characters.
        type: str
        required: true
      security_level:
        description:
          - Security mechanism used for communication between agent and manager.
        type: str
        choices: [AuthPriv, AuthNoPriv]
        default: AuthPriv
      auth_password:
        description:
          - Authorization password for the user.
          - Required when security_level is AuthPriv or AuthNoPriv.
        type: str
        required: true
      privacy_password:
        description:
          - Privacy password for the SNMP user.
          - Required when security_level is AuthPriv.
        type: str
  snmp_traps:
    description:
      - List of SNMP trap destinations.
    type: list
    elements: dict
    suboptions:
      enabled:
        description:
          - Enables/disables the trap on the server If enabled, trap is active on the server.
        type: bool
        default: true
      version:
        description:
          - SNMP version for the trap.
        type: str
        choices: [V2, V3]
        required: true
      community:
        description:
          - SNMP community group used for sending SNMP trap to other devices.
          - Applicable only for SNMP v2c.
        type: str
      user:
        description:
          - SNMP user for the trap.
          - Applicable only to SNMPv3.
        type: str
      type:
        description:
          - Type of trap which decides whether to receive a notification when a trap is received at the destination.
          - Note that 'Inform' is only supported for V2 traps, V3 traps only support 'Trap' type.
        type: str
        choices: [Trap, Inform]
        default: Trap
      destination:
        description:
          - IP address or hostname of the trap destination.
        type: str
        required: true
      port:
        description:
          - Port number for the trap destination.
        type: int
        default: 162
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
- name: Create SNMP Policy with SNMPv2 and SNMPv3 enabled
  cisco.intersight.intersight_snmp_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "mixed-snmp-policy"
    description: "SNMP policy with both v2 and v3 enabled"
    enabled: true
    v2c_enabled: true
    v3_enabled: true
    snmp_port: 161
    sys_contact: "admin@example.com"
    sys_location: "Data Center A"
    community_access: "Full"
    access_community_string: "public"
    trap_community: "trapcomm"
    engine_input_id: "custom-engine-id"
    snmp_users:
      - name: "admin"
        security_level: "AuthPriv"
        auth_password: "authpassword123"
        privacy_password: "privpassword123"
      - name: "readonly"
        security_level: "AuthNoPriv"
        auth_password: "readonlypass123"
    snmp_traps:
      - enabled: true
        version: "V2"
        community: "trapcomm"
        type: "Trap"
        destination: "192.168.1.100"
        port: 162
      - enabled: true
        version: "V3"
        user: "admin"
        type: "Trap"
        destination: "192.168.1.101"
        port: 162
    tags:
      - Key: "Environment"
        Value: "Production"
    state: present

- name: Create SNMP Policy with only SNMPv3 enabled
  cisco.intersight.intersight_snmp_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "v3-only-snmp-policy"
    description: "SNMP policy with only v3 enabled"
    enabled: true
    v2c_enabled: false
    v3_enabled: true
    snmp_port: 161
    sys_contact: "admin@example.com"
    sys_location: "Data Center B"
    engine_input_id: "v3-engine-id"
    snmp_users:
      - name: "v3user"
        security_level: "AuthPriv"
        auth_password: "v3authpass123"
        privacy_password: "v3privpass123"
    state: present

- name: Create SNMP Policy with only SNMPv2 enabled
  cisco.intersight.intersight_snmp_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "v2-only-snmp-policy"
    description: "SNMP policy with only v2 enabled"
    enabled: true
    v2c_enabled: true
    v3_enabled: false
    snmp_port: 161
    sys_contact: "admin@example.com"
    sys_location: "Data Center C"
    community_access: "Limited"
    access_community_string: "readonly"
    trap_community: "v2traps"
    state: present

- name: Create disabled SNMP Policy
  cisco.intersight.intersight_snmp_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "disabled-snmp-policy"
    description: "Disabled SNMP policy"
    enabled: false
    state: present

- name: Delete SNMP Policy
  cisco.intersight.intersight_snmp_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "mixed-snmp-policy"
    state: absent
'''

RETURN = r'''
api_response:
  description: The API response output returned by the specified resource.
  returned: always
  type: dict
  sample:
    "api_response": {
        "Name": "mixed-snmp-policy",
        "ObjectType": "snmp.Policy",
        "Enabled": true,
        "V2Enabled": true,
        "V3Enabled": true,
        "SnmpPort": 161,
        "SysContact": "admin@example.com",
        "SysLocation": "Data Center A",
        "CommunityAccess": "Full",
        "AccessCommunityString": "public",
        "TrapCommunity": "trapcomm",
        "EngineId": "custom-engine-id",
        "SnmpUsers": [
            {
                "Name": "admin",
                "SecurityLevel": "AuthPriv",
                "AuthType": "SHA",
                "IsAuthPasswordSet": true,
                "PrivacyType": "AES",
                "IsPrivacyPasswordSet": true
            }
        ],
        "SnmpTraps": [
            {
                "Enabled": true,
                "Version": "V2",
                "Community": "trapcomm",
                "Type": "Trap",
                "Destination": "192.168.1.100",
                "Port": 162
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


def get_argument_spec():
    snmp_user_spec = dict(
        name=dict(type='str', required=True),
        security_level=dict(type='str', choices=['AuthPriv', 'AuthNoPriv'], default='AuthPriv'),
        auth_password=dict(type='str', no_log=True, required=True),
        privacy_password=dict(type='str', no_log=True)
    )

    snmp_trap_spec = dict(
        enabled=dict(type='bool', default=True),
        version=dict(type='str', choices=['V2', 'V3'], required=True),
        community=dict(type='str'),
        user=dict(type='str'),
        type=dict(type='str', choices=['Trap', 'Inform'], default='Trap'),
        destination=dict(type='str', required=True),
        port=dict(type='int', default=162)
    )

    argument_spec = intersight_argument_spec.copy()
    argument_spec.update(
        state=dict(type='str', choices=['present', 'absent'], default='present'),
        organization=dict(type='str', default='default'),
        name=dict(type='str', required=True),
        description=dict(type='str', aliases=['descr']),
        tags=dict(type='list', elements='dict'),
        enabled=dict(type='bool', default=True),
        v2c_enabled=dict(type='bool', default=True),
        v3_enabled=dict(type='bool', default=True),
        snmp_port=dict(type='int', default=161),
        sys_contact=dict(type='str'),
        sys_location=dict(type='str'),
        community_access=dict(type='str', choices=['Disabled', 'Limited', 'Full'], default='Disabled'),
        access_community_string=dict(type='str'),
        trap_community=dict(type='str'),
        engine_input_id=dict(type='str'),
        snmp_users=dict(type='list', elements='dict', options=snmp_user_spec),
        snmp_traps=dict(type='list', elements='dict', options=snmp_trap_spec)
    )
    return argument_spec


def validate_snmp_configuration(module):
    """
    Validate SNMP configuration parameters.
    """
    params = module.params
    if params['state'] == 'present':
        # If SNMP is disabled, we don't need to validate other parameters
        if not params['enabled']:
            return

        # If SNMP is enabled, at least one version must be enabled
        if not params['v2c_enabled'] and not params['v3_enabled']:
            module.fail_json(msg="At least one of v2c_enabled or v3_enabled must be true when SNMP is enabled")

        # Check if both sys_contact and sys_location are provided when SNMP is enabled
        if not params.get('sys_contact') or not params.get('sys_location'):
            module.fail_json(msg="sys_contact and sys_location are required when SNMP is enabled")

        # SNMPv3 users can only be specified when SNMPv3 is enabled
        if not params['v3_enabled'] and params.get('snmp_users'):
            module.fail_json(msg="snmp_users cannot be specified when v3_enabled is false")

        # SNMPv3 only specific validations
        if params['v3_enabled'] and not params['v2c_enabled']:
            # For SNMPv3, community access is always Disabled
            if params['community_access'] != 'Disabled':
                module.fail_json(msg="community_access must be 'Disabled' when v3_enabled is true and v2c_enabled is false")

        # Validate SNMP users
        if params.get('snmp_users'):
            for user in params['snmp_users']:
                if not user.get('auth_password'):
                    module.fail_json(msg="auth_password is required for security_level 'AuthPriv' or 'AuthNoPriv'")

                if user['security_level'] == 'AuthPriv' and not user.get('privacy_password'):
                    module.fail_json(msg="privacy_password is required for security_level 'AuthPriv'")

        # Validate SNMP traps
        if params.get('snmp_traps'):
            for trap in params['snmp_traps']:
                if trap['version'] == 'V2' and not params['v2c_enabled']:
                    module.fail_json(msg="SNMP trap version 'V2' is not supported when v2c_enabled is false")
                elif trap['version'] == 'V3' and not params['v3_enabled']:
                    module.fail_json(msg="SNMP trap version 'V3' is not supported when v3_enabled is false")

                if trap['version'] == 'V2' and not trap.get('community'):
                    module.fail_json(msg="community is required for SNMP trap version 'V2'")
                elif trap['version'] == 'V3' and not trap.get('user'):
                    module.fail_json(msg="user is required for SNMP trap version 'V3'")

                # V3 traps only support 'Trap' type, not 'Inform'
                if trap['version'] == 'V3' and trap.get('type') == 'Inform':
                    module.fail_json(msg="SNMP trap version 'V3' does not support type 'Inform', only 'Trap' is supported")


def build_snmp_users(snmp_users):
    """
    Build SNMP users list for API body.

    Args:
        snmp_users: List of SNMP user dictionaries

    Returns:
        list: List of SNMP user dictionaries formatted for API
    """
    if not snmp_users:
        return []

    users = []
    for user in snmp_users:
        snmp_user = {
            'Name': user['name'],
            'SecurityLevel': user['security_level'],
            'AuthType': 'SHA',
            'AuthPassword': user['auth_password']
        }

        # Only add privacy type and password if security level is AuthPriv
        if user.get('security_level') == 'AuthPriv':
            snmp_user['PrivacyType'] = 'AES'
            snmp_user['PrivacyPassword'] = user['privacy_password']

        users.append(snmp_user)

    return users


def build_snmp_traps(snmp_traps):
    """
    Build SNMP traps list for API body.

    Args:
        snmp_traps: List of SNMP trap dictionaries

    Returns:
        list: List of SNMP trap dictionaries formatted for API
    """
    if not snmp_traps:
        return []

    traps = []
    for trap in snmp_traps:
        snmp_trap = {
            'Enabled': trap['enabled'],
            'Version': trap['version'],
            'Type': trap['type'],
            'Destination': trap['destination'],
            'Port': trap['port'],
        }

        if trap['version'] == 'V3':
            snmp_trap['User'] = trap['user']
        elif trap['version'] == 'V2':
            snmp_trap['Community'] = trap['community']

        traps.append(snmp_trap)

    return traps


def build_api_body(intersight):
    """
    Build the API body for SNMP policy configuration.

    Args:
        intersight: IntersightModule instance

    Returns:
        None: Updates intersight.api_body directly
    """
    params = intersight.module.params
    if params['state'] == 'present':
        # Base API body
        intersight.api_body = {
            'Organization': {
                'Name': params['organization'],
            },
            'Name': params['name'],
            'Enabled': params['enabled']
        }

        # Only include additional parameters if SNMP is enabled
        if params['enabled']:
            # Add version-specific parameters
            intersight.api_body['V2Enabled'] = params.get('v2c_enabled', True)
            intersight.api_body['V3Enabled'] = params.get('v3_enabled', True)

            # Add SNMP port
            intersight.api_body['SnmpPort'] = params['snmp_port']

            # Add system contact and location
            intersight.api_body['SysContact'] = params['sys_contact']
            intersight.api_body['SysLocation'] = params['sys_location']

            # Add community access
            intersight.api_body['CommunityAccess'] = params['community_access']

            # Add SNMPv2c specific parameters
            if params['v2c_enabled']:
                if params.get('access_community_string'):
                    intersight.api_body['AccessCommunityString'] = params['access_community_string']
                if params.get('trap_community'):
                    intersight.api_body['TrapCommunity'] = params['trap_community']

            # Add SNMPv3 specific parameters
            if params['v3_enabled']:
                if params.get('engine_input_id'):
                    intersight.api_body['EngineId'] = params['engine_input_id']

            # Add SNMP users
            intersight.api_body['SnmpUsers'] = build_snmp_users(params.get('snmp_users'))

            # Add SNMP traps
            intersight.api_body['SnmpTraps'] = build_snmp_traps(params.get('snmp_traps'))

        else:
            # When SNMP is disabled, send empty arrays
            intersight.api_body['SnmpUsers'] = []
            intersight.api_body['SnmpTraps'] = []

        # Add optional parameters
        intersight.set_tags_and_description()


def main():
    # Get the argument specification
    argument_spec = get_argument_spec()

    # Create the module
    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True,
    )

    # Validate SNMP configuration
    validate_snmp_configuration(module)

    # Initialize Intersight module
    intersight = IntersightModule(module)
    intersight.result['api_response'] = {}
    intersight.result['trace_id'] = ''

    # Build API body
    build_api_body(intersight)

    # Resource path used to configure policy
    resource_path = '/snmp/Policies'

    # Configure the policy
    intersight.configure_policy_or_profile(resource_path=resource_path)

    # Exit with results
    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
