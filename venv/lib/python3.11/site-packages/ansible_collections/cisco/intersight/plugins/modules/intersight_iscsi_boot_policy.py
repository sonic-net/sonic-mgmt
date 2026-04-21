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
module: intersight_iscsi_boot_policy
short_description: Manage iSCSI Boot Policies for Cisco Intersight
description:
  - Create, update, and delete iSCSI Boot Policies on Cisco Intersight.
  - iSCSI boot policies define how servers boot from iSCSI targets using IPv4 or IPv6 protocols.
  - Supports automatic target discovery (Auto) and manual configuration (Static) with DHCP, Pool, or Static IP sources.
  - For more information see L(Cisco Intersight,https://intersight.com/apidocs/vnic/IscsiBootPolicies/get/).
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
      - Policies created within a Custom Organization are applicable only to devices in the same Organization.
      - Use 'default' for the default organization.
    type: str
    default: default
  name:
    description:
      - The name assigned to the iSCSI Boot Policy.
      - Must be unique within the organization.
      - The name must be between 1 and 62 alphanumeric characters, allowing special characters :-_.
    type: str
    required: true
  description:
    description:
      - The user-defined description for the iSCSI Boot Policy.
      - Description can contain letters(a-z, A-Z), numbers(0-9), hyphen(-), period(.), colon(:), or an underscore(_).
    type: str
    aliases: [descr]
  tags:
    description:
      - List of tags in Key:<user-defined key> Value:<user-defined value> format.
    type: list
    elements: dict
  iscsi_ip_type:
    description:
      - Type of the IP address requested for iSCSI vNIC - IPv4/IPv6.
      - ipv4 supports both auto and static target source types.
      - ipv6 only supports static target source type (not auto).
      - Both ipv4 and ipv6 support dhcp, pool, and static initiator IP sources.
    type: str
    choices: [ipv4, ipv6]
    default: ipv4
  target_source_type:
    description:
      - Target discovery method.
      - auto - Automatic target discovery using DHCP vendor ID/IQN.
      - static - Manual target configuration using target policies.
    type: str
    choices: [auto, static]
    default: static
  auto_targetvendor_name:
    description:
      - Auto target interface that is represented via the Initiator name or the DHCP vendor ID.
      - The vendor ID can be up to 64 characters.
      - Required when target_source_type is auto and iscsi_ip_type is ipv4.
    type: str
  iscsi_adapter_policy_name:
    description:
      - Relationship to the iSCSI Adapter Policy.
      - Name of the iSCSI adapter policy to associate with this boot policy.
      - Optional for all configurations.
    type: str
  primary_target_policy_name:
    description:
      - Specifies Target Profile information for iSCSI Boot.
      - Name of the primary iSCSI static target policy.
      - Required when target_source_type is static.
    type: str
  secondary_target_policy_name:
    description:
      - Specifies Target Profile information for iSCSI Boot.
      - Optional when target_source_type is static.
    type: str
  chap:
    description:
      - CHAP authentication parameters for iSCSI Target.
      - Provide user_id and password to enable CHAP authentication.
      - Leave empty or omit to disable CHAP authentication.
    type: dict
    suboptions:
      user_id:
        description:
          - CHAP username for authentication.
        type: str
        required: true
      password:
        description:
          - CHAP password for authentication.
        type: str
        required: true
  mutual_chap:
    description:
      - Mutual CHAP authentication parameters for iSCSI Initiator.
      - Two-way CHAP mechanism.
      - Provide user_id and password to enable Mutual CHAP authentication.
      - Leave empty or omit to disable Mutual CHAP authentication.
    type: dict
    suboptions:
      user_id:
        description:
          - Mutual CHAP username for authentication.
        type: str
        required: true
      password:
        description:
          - Mutual CHAP password for authentication.
        type: str
        required: true
  initiator_ip_source:
    description:
      - Method for assigning initiator IP address.
      - dhcp - Obtain IP address automatically via DHCP.
      - pool - Use an IP pool for address assignment.
      - static - Manually configure static IP address.
    type: str
    choices: [dhcp, pool, static]
    default: dhcp
  initiator_ip_pool_name:
    description:
      - Name of the IP pool to use for initiator IP address assignment.
      - Required when initiator_ip_source is pool.
    type: str
  initiator_static_ipv4_address:
    description:
      - Static IPv4 address provided for iSCSI Initiator.
      - Required when initiator_ip_source is static and iscsi_ip_type is ipv4.
    type: str
  initiator_static_ipv4_netmask:
    description:
      - A subnet mask is a 32-bit number that masks an IP address and divides the IP address into network address and host address.
      - Required when initiator_ip_source is static and iscsi_ip_type is ipv4.
    type: str
  initiator_static_ipv4_gateway:
    description:
      - IP address of the default IPv4 gateway.
      - Required when initiator_ip_source is static and iscsi_ip_type is ipv4.
    type: str
  initiator_static_ipv4_primary_dns:
    description:
      - IP Address of the primary Domain Name System (DNS) server.
      - Optional when initiator_ip_source is static and iscsi_ip_type is ipv4.
    type: str
  initiator_static_ipv4_secondary_dns:
    description:
      - IP Address of the secondary Domain Name System (DNS) server.
      - Optional when initiator_ip_source is static and iscsi_ip_type is ipv4.
    type: str
  initiator_static_ipv6_address:
    description:
      - Static IPv6 address provided for iSCSI Initiator.
      - Required when initiator_ip_source is static and iscsi_ip_type is ipv6.
    type: str
  initiator_static_ipv6_prefix:
    description:
      - The integer length of the prefix that masks the IP address and divides it into network and host addresses.
      - Required when initiator_ip_source is static and iscsi_ip_type is ipv6.
    type: int
  initiator_static_ipv6_gateway:
    description:
      - IP address of the default IPv6 gateway.
      - Required when initiator_ip_source is static and iscsi_ip_type is ipv6.
    type: str
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
- name: Create iSCSI Boot Policy with Auto discovery (IPv4)
  cisco.intersight.intersight_iscsi_boot_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "iscsi-boot-auto"
    description: "iSCSI boot policy with auto discovery"
    iscsi_ip_type: "ipv4"
    target_source_type: "auto"
    auto_targetvendor_name: "iqn.1991-05.com.cisco"
    iscsi_adapter_policy_name: "iscsi-adapter-policy"
    initiator_ip_source: "dhcp"
    state: present

- name: Create iSCSI Boot Policy with Static targets and DHCP initiator (IPv4)
  cisco.intersight.intersight_iscsi_boot_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "iscsi-boot-static-dhcp"
    description: "iSCSI boot policy with static targets"
    iscsi_ip_type: "ipv4"
    target_source_type: "static"
    primary_target_policy_name: "primary-target-policy"
    secondary_target_policy_name: "secondary-target-policy"
    chap:
      user_id: "chapuser"
      password: "chappassword123"
    mutual_chap:
      user_id: "mutualuser"
      password: "mutualpassword123"
    initiator_ip_source: "dhcp"
    state: present

- name: Create iSCSI Boot Policy with Pool-based initiator IP
  cisco.intersight.intersight_iscsi_boot_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "iscsi-boot-pool"
    description: "iSCSI boot policy with IP pool"
    iscsi_ip_type: "ipv4"
    target_source_type: "static"
    primary_target_policy_name: "primary-target-policy"
    initiator_ip_source: "pool"
    initiator_ip_pool_name: "iscsi-ip-pool"
    state: present

- name: Create iSCSI Boot Policy with Static IPv4 configuration
  cisco.intersight.intersight_iscsi_boot_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "iscsi-boot-static-ipv4"
    description: "iSCSI boot policy with static IPv4"
    iscsi_ip_type: "ipv4"
    target_source_type: "static"
    primary_target_policy_name: "primary-target-policy"
    initiator_ip_source: "static"
    initiator_static_ipv4_address: "192.168.1.100"
    initiator_static_ipv4_netmask: "255.255.255.0"
    initiator_static_ipv4_gateway: "192.168.1.1"
    initiator_static_ipv4_primary_dns: "8.8.8.8"
    initiator_static_ipv4_secondary_dns: "8.8.4.4"
    tags:
      - Key: Environment
        Value: Production
    state: present

- name: Create iSCSI Boot Policy with Static IPv6 configuration
  cisco.intersight.intersight_iscsi_boot_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "iscsi-boot-static-ipv6"
    description: "iSCSI boot policy with static IPv6"
    iscsi_ip_type: "ipv6"
    target_source_type: "static"
    primary_target_policy_name: "primary-target-policy-ipv6"
    initiator_ip_source: "static"
    initiator_static_ipv6_address: "2001:db8::1"
    initiator_static_ipv6_prefix: 64
    initiator_static_ipv6_gateway: "2001:db8::ffff"
    state: present

- name: Create iSCSI Boot Policy with IPv6 DHCP initiator
  cisco.intersight.intersight_iscsi_boot_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "iscsi-boot-ipv6-dhcp"
    description: "iSCSI boot policy with IPv6 DHCP"
    iscsi_ip_type: "ipv6"
    target_source_type: "static"
    primary_target_policy_name: "primary-target-policy-ipv6"
    initiator_ip_source: "dhcp"
    state: present

- name: Create iSCSI Boot Policy with IPv6 Pool initiator
  cisco.intersight.intersight_iscsi_boot_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "iscsi-boot-ipv6-pool"
    description: "iSCSI boot policy with IPv6 pool"
    iscsi_ip_type: "ipv6"
    target_source_type: "static"
    primary_target_policy_name: "primary-target-policy-ipv6"
    initiator_ip_source: "pool"
    initiator_ip_pool_name: "ipv6-ip-pool"
    state: present

- name: Delete iSCSI Boot Policy
  cisco.intersight.intersight_iscsi_boot_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "iscsi-boot-auto"
    state: absent
'''

RETURN = r'''
api_response:
  description: The API response output returned by the specified resource.
  returned: always
  type: dict
  sample:
    "api_response": {
        "Name": "iscsi-boot-auto",
        "ObjectType": "vnic.IscsiBootPolicy",
        "IscsiIpType": "IPv4",
        "TargetSourceType": "Auto",
        "AutoTargetvendorName": "iqn.1991-05.com.cisco",
        "InitiatorIpSource": "DHCP",
        "Moid": "1234567890abcdef12345678",
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


def validate_parameters(module):
    """
    Validate module parameters for iSCSI boot policy configuration.
    """
    if module.params['state'] != 'present':
        return

    # Validate required parameters for present state
    if not module.params.get('iscsi_ip_type'):
        module.fail_json(msg="Parameter 'iscsi_ip_type' is required when state is present")
    if not module.params.get('target_source_type'):
        module.fail_json(msg="Parameter 'target_source_type' is required when state is present")
    if not module.params.get('initiator_ip_source'):
        module.fail_json(msg="Parameter 'initiator_ip_source' is required when state is present")

    # Validate target source type requirements
    if module.params['target_source_type'] == 'auto':
        if not module.params.get('auto_targetvendor_name'):
            module.fail_json(msg="Parameter 'auto_targetvendor_name' is required when target_source_type is auto")
    elif module.params['target_source_type'] == 'static':
        if not module.params.get('primary_target_policy_name'):
            module.fail_json(msg="Parameter 'primary_target_policy_name' is required when target_source_type is static")

    # Validate initiator IP source requirements
    if module.params['initiator_ip_source'] == 'pool':
        if not module.params.get('initiator_ip_pool_name'):
            module.fail_json(msg="Parameter 'initiator_ip_pool_name' is required when initiator_ip_source is pool")

    # Validate IPv6 doesn't use Auto target source
    if module.params['iscsi_ip_type'] == 'ipv6' and module.params['target_source_type'] == 'auto':
        module.fail_json(msg="ipv6 only supports static target source type, not auto")

    # Validate Static IPv4 configuration
    if module.params['iscsi_ip_type'] == 'ipv4' and module.params['initiator_ip_source'] == 'static':
        required_ipv4_params = ['initiator_static_ipv4_address', 'initiator_static_ipv4_netmask', 'initiator_static_ipv4_gateway']
        for param in required_ipv4_params:
            if not module.params.get(param):
                module.fail_json(msg=f"Parameter '{param}' is required when initiator_ip_source is static and iscsi_ip_type is ipv4")

    # Validate Static IPv6 configuration
    if module.params['iscsi_ip_type'] == 'ipv6' and module.params['initiator_ip_source'] == 'static':
        required_ipv6_params = ['initiator_static_ipv6_address', 'initiator_static_ipv6_prefix', 'initiator_static_ipv6_gateway']
        for param in required_ipv6_params:
            if not module.params.get(param):
                module.fail_json(msg=f"Parameter '{param}' is required when initiator_ip_source is static and iscsi_ip_type is ipv6")


def main():
    argument_spec = intersight_argument_spec.copy()
    argument_spec.update(
        state=dict(type='str', choices=['present', 'absent'], default='present'),
        organization=dict(type='str', default='default'),
        name=dict(type='str', required=True),
        description=dict(type='str', aliases=['descr']),
        tags=dict(type='list', elements='dict'),
        iscsi_ip_type=dict(type='str', choices=['ipv4', 'ipv6'], default='ipv4'),
        target_source_type=dict(type='str', choices=['auto', 'static'], default='static'),
        auto_targetvendor_name=dict(type='str'),
        iscsi_adapter_policy_name=dict(type='str'),
        primary_target_policy_name=dict(type='str'),
        secondary_target_policy_name=dict(type='str'),
        chap=dict(type='dict', options=dict(
            user_id=dict(type='str', required=True),
            password=dict(type='str', required=True, no_log=True)
        )),
        mutual_chap=dict(type='dict', options=dict(
            user_id=dict(type='str', required=True),
            password=dict(type='str', required=True, no_log=True)
        )),
        initiator_ip_source=dict(type='str', choices=['dhcp', 'pool', 'static'], default='dhcp'),
        initiator_ip_pool_name=dict(type='str'),
        initiator_static_ipv4_address=dict(type='str'),
        initiator_static_ipv4_netmask=dict(type='str'),
        initiator_static_ipv4_gateway=dict(type='str'),
        initiator_static_ipv4_primary_dns=dict(type='str'),
        initiator_static_ipv4_secondary_dns=dict(type='str'),
        initiator_static_ipv6_address=dict(type='str'),
        initiator_static_ipv6_prefix=dict(type='int'),
        initiator_static_ipv6_gateway=dict(type='str'),
    )

    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True,
    )

    intersight = IntersightModule(module)
    intersight.result['api_response'] = {}
    intersight.result['trace_id'] = ''

    # Validate module parameters
    validate_parameters(module)

    # Resource path used to configure policy
    resource_path = '/vnic/IscsiBootPolicies'

    # Define API body used in compares or create
    intersight.api_body = {
        'Organization': {
            'Name': module.params['organization'],
        },
        'Name': module.params['name'],
    }

    if module.params['state'] == 'present':
        # Convert to proper API format: ipv4 -> IPv4, ipv6 -> IPv6
        if module.params['iscsi_ip_type'] == 'ipv4':
            intersight.api_body['IscsiIpType'] = 'IPv4'
        else:
            intersight.api_body['IscsiIpType'] = 'IPv6'
        intersight.api_body['TargetSourceType'] = module.params['target_source_type'].capitalize()
        intersight.api_body['InitiatorIpSource'] = module.params['initiator_ip_source'].upper() if module.params['initiator_ip_source'] == 'dhcp' \
            else module.params['initiator_ip_source'].capitalize()

        intersight.set_tags_and_description()

        # Handle Auto target source configuration
        if module.params['target_source_type'] == 'auto':
            intersight.api_body['AutoTargetvendorName'] = module.params['auto_targetvendor_name']
        else:
            # Handle Static target source configuration
            # Get primary target policy MOID
            primary_target_moid = intersight.get_moid_by_name_and_org(
                resource_path='/vnic/IscsiStaticTargetPolicies',
                resource_name=module.params['primary_target_policy_name'],
                organization_name=module.params['organization']
            )
            if not primary_target_moid:
                module.fail_json(
                    msg=f"Primary target policy '{module.params['primary_target_policy_name']}' not found in organization '{module.params['organization']}'")
            intersight.api_body['PrimaryTargetPolicy'] = primary_target_moid
            # Get secondary target policy MOID if specified
            if module.params.get('secondary_target_policy_name'):
                secondary_target_moid = intersight.get_moid_by_name_and_org(
                    resource_path='/vnic/IscsiStaticTargetPolicies',
                    resource_name=module.params['secondary_target_policy_name'],
                    organization_name=module.params['organization']
                )
                if not secondary_target_moid:
                    module.fail_json(
                        msg=f"Secondary target policy '{module.params['secondary_target_policy_name']}' not found \
                        in organization '{module.params['organization']}'")
                intersight.api_body['SecondaryTargetPolicy'] = secondary_target_moid

        # Handle iSCSI adapter policy if specified
        if module.params.get('iscsi_adapter_policy_name'):
            adapter_policy_moid = intersight.get_moid_by_name_and_org(
                resource_path='/vnic/IscsiAdapterPolicies',
                resource_name=module.params['iscsi_adapter_policy_name'],
                organization_name=module.params['organization']
            )
            if not adapter_policy_moid:
                module.fail_json(
                    msg=f"iSCSI adapter policy '{module.params['iscsi_adapter_policy_name']}' not found in organization '{module.params['organization']}'")
            intersight.api_body['IscsiAdapterPolicy'] = adapter_policy_moid
        # Handle CHAP authentication
        chap_config = {
            'UserId': '',
            'Password': '',
            'IsPasswordSet': False
        }
        if module.params.get('chap'):
            chap_config['UserId'] = module.params['chap']['user_id']
            chap_config['Password'] = module.params['chap']['password']
        intersight.api_body['Chap'] = chap_config
        # Handle Mutual CHAP authentication
        mutual_chap_config = {
            'UserId': '',
            'Password': '',
            'IsPasswordSet': False
        }
        if module.params.get('mutual_chap'):
            mutual_chap_config['UserId'] = module.params['mutual_chap']['user_id']
            mutual_chap_config['Password'] = module.params['mutual_chap']['password']
        intersight.api_body['MutualChap'] = mutual_chap_config

        # Handle initiator IP configuration based on IP source
        if module.params['initiator_ip_source'] == 'pool':
            # Get IP pool MOID
            ip_pool_moid = intersight.get_moid_by_name_and_org(
                resource_path='/ippool/Pools',
                resource_name=module.params['initiator_ip_pool_name'],
                organization_name=module.params['organization']
            )
            if not ip_pool_moid:
                module.fail_json(msg=f"IP pool '{module.params['initiator_ip_pool_name']}' not found in organization '{module.params['organization']}'")
            intersight.api_body['InitiatorIpPool'] = ip_pool_moid
        elif module.params['initiator_ip_source'] == 'static':
            if module.params['iscsi_ip_type'] == 'ipv4':
                intersight.api_body['InitiatorStaticIpV4Address'] = module.params['initiator_static_ipv4_address']
                ipv4_config = {
                    'Netmask': module.params['initiator_static_ipv4_netmask'],
                    'Gateway': module.params['initiator_static_ipv4_gateway']
                }
                if module.params.get('initiator_static_ipv4_primary_dns'):
                    ipv4_config['PrimaryDns'] = module.params['initiator_static_ipv4_primary_dns']
                if module.params.get('initiator_static_ipv4_secondary_dns'):
                    ipv4_config['SecondaryDns'] = module.params['initiator_static_ipv4_secondary_dns']
                intersight.api_body['InitiatorStaticIpV4Config'] = ipv4_config
            else:
                # IPv6 configuration
                intersight.api_body['InitiatorStaticIpV6Address'] = module.params['initiator_static_ipv6_address']
                ipv6_config = {
                    'Prefix': module.params['initiator_static_ipv6_prefix'],
                    'Gateway': module.params['initiator_static_ipv6_gateway']
                }
                intersight.api_body['InitiatorStaticIpV6Config'] = ipv6_config

    intersight.configure_policy_or_profile(resource_path=resource_path)

    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
