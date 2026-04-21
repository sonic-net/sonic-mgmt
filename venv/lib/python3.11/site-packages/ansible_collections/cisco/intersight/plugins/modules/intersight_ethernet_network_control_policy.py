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
module: intersight_ethernet_network_control_policy
short_description: Ethernet Network Control Policy configuration for Cisco Intersight
description:
  - Manages Ethernet Network Control Policy configuration on Cisco Intersight.
  - A policy to configure network control settings for ethernet connections on Cisco Intersight managed servers.
  - This policy is applicable only for UCS Servers (FI-Attached).
  - For more information see L(Cisco Intersight,https://intersight.com/apidocs/fabric/EthNetworkControlPolicy/get/).
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
      - The name assigned to the Ethernet Network Control Policy.
      - The name must be between 1 and 62 alphanumeric characters, allowing special characters :-_.
    type: str
    required: true
  description:
    description:
      - The user-defined description for the Ethernet Network Control Policy.
      - Description can contain letters(a-z, A-Z), numbers(0-9), hyphen(-), period(.), colon(:), or an underscore(_).
    type: str
    aliases: [descr]
  tags:
    description:
      - List of tags in Key:<user-defined key> Value:<user-defined value> format.
    type: list
    elements: dict
  cdp_enabled:
    description:
      - Enables the CDP on an interface.
      - Cisco Discovery Protocol (CDP) is a proprietary Data Link Layer protocol developed by Cisco Systems.
    type: bool
    default: false
  mac_registration_mode:
    description:
      - Determines the MAC addresses that have to be registered with the switch.
      - nativeVlanOnly - Register only the MAC addresses learned in the native VLAN.
      - allVlans - Register the MAC addresses learned in all VLANs.
    type: str
    choices: ['nativeVlanOnly', 'allVlans']
    default: 'nativeVlanOnly'
  uplink_fail_action:
    description:
      - Determines the state of the virtual interface (vethernet / vfc) on the switch when a suitable uplink is not pinned.
      - linkDown - The vethernet will go down.
      - warning - The vethernet will remain up and will not fail over if uplink connectivity is lost.
      - "Important! If the Action on Uplink is set to Warning, the switch will not fail over if uplink connectivity is lost."
    type: str
    choices: ['linkDown', 'warning']
    default: 'linkDown'
  forge_mac:
    description:
      - Determines if the MAC forging is allowed or denied on an interface.
      - allow - Allows MAC forging on the interface.
      - deny - Denies MAC forging on the interface.
    type: str
    choices: ['allow', 'deny']
    default: 'allow'
  lldp_transmit_enabled:
    description:
      - Determines if the LLDP frames can be transmitted by an interface on the switch.
      - Link Layer Discovery Protocol (LLDP) is a vendor-neutral link layer protocol.
    type: bool
    default: false
  lldp_receive_enabled:
    description:
      - Determines if the LLDP frames can be received by an interface on the switch.
      - Link Layer Discovery Protocol (LLDP) is a vendor-neutral link layer protocol.
    type: bool
    default: false
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
- name: Create an Ethernet Network Control Policy with default settings
  cisco.intersight.intersight_ethernet_network_control_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "default-network-control-policy"
    description: "Default Ethernet Network Control policy"
    state: present

- name: Create an Ethernet Network Control Policy with CDP and LLDP enabled
  cisco.intersight.intersight_ethernet_network_control_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "discovery-enabled-policy"
    description: "Network Control policy with discovery protocols enabled"
    tags:
      - Key: "Environment"
        Value: "Production"
    cdp_enabled: true
    mac_registration_mode: "allVlans"
    uplink_fail_action: "warning"
    forge_mac: "deny"
    lldp_transmit_enabled: true
    lldp_receive_enabled: true
    state: present

- name: Create an Ethernet Network Control Policy with strict security settings
  cisco.intersight.intersight_ethernet_network_control_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "secure-network-control-policy"
    description: "Secure Network Control policy with MAC forging denied"
    cdp_enabled: false
    mac_registration_mode: "nativeVlanOnly"
    uplink_fail_action: "linkDown"
    forge_mac: "deny"
    lldp_transmit_enabled: false
    lldp_receive_enabled: false
    state: present

- name: Delete an Ethernet Network Control Policy
  cisco.intersight.intersight_ethernet_network_control_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "secure-network-control-policy"
    state: absent
'''

RETURN = r'''
api_response:
  description: The API response output returned by the specified resource.
  returned: always
  type: dict
  sample:
    "api_response": {
        "Name": "discovery-enabled-policy",
        "ObjectType": "fabric.EthNetworkControlPolicy",
        "CdpEnabled": true,
        "MacRegistrationMode": "allVlans",
        "UplinkFailAction": "warning",
        "ForgeMac": "deny",
        "LldpSettings": {
            "TransmitEnabled": true,
            "ReceiveEnabled": true
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


def main():
    argument_spec = intersight_argument_spec.copy()
    argument_spec.update(
        state=dict(type='str', choices=['present', 'absent'], default='present'),
        organization=dict(type='str', default='default'),
        name=dict(type='str', required=True),
        description=dict(type='str', aliases=['descr']),
        tags=dict(type='list', elements='dict'),
        cdp_enabled=dict(type='bool', default=False),
        mac_registration_mode=dict(
            type='str',
            choices=['nativeVlanOnly', 'allVlans'],
            default='nativeVlanOnly'
        ),
        uplink_fail_action=dict(
            type='str',
            choices=['linkDown', 'warning'],
            default='linkDown'
        ),
        forge_mac=dict(
            type='str',
            choices=['allow', 'deny'],
            default='allow'
        ),
        lldp_transmit_enabled=dict(type='bool', default=False),
        lldp_receive_enabled=dict(type='bool', default=False),
    )
    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True,
    )

    intersight = IntersightModule(module)
    intersight.result['api_response'] = {}
    intersight.result['trace_id'] = ''

    # Resource path used to configure policy
    resource_path = '/fabric/EthNetworkControlPolicies'

    # Define API body used in compares or create
    intersight.api_body = {
        'Organization': {
            'Name': intersight.module.params['organization'],
        },
        'Name': intersight.module.params['name']
    }

    if module.params['state'] == 'present':
        intersight.set_tags_and_description()

        intersight.api_body['CdpEnabled'] = module.params['cdp_enabled']
        intersight.api_body['MacRegistrationMode'] = module.params['mac_registration_mode']
        intersight.api_body['UplinkFailAction'] = module.params['uplink_fail_action']
        intersight.api_body['ForgeMac'] = module.params['forge_mac']
        intersight.api_body['LldpSettings'] = {
            'TransmitEnabled': module.params['lldp_transmit_enabled'],
            'ReceiveEnabled': module.params['lldp_receive_enabled']
        }

    intersight.configure_policy_or_profile(resource_path=resource_path)

    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
