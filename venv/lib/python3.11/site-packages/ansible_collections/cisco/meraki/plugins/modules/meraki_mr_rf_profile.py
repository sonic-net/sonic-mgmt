#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Kevin Breit (@kbreit) <kevin.breit@kevinbreit.net>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    "status": ['deprecated'],
    'supported_by': 'community'
}

DOCUMENTATION = r'''
---
module: meraki_mr_rf_profile
short_description: Manage RF profiles for Meraki wireless networks
description:
- Allows for configuration of radio frequency (RF)  profiles in Meraki MR wireless networks.
deprecated:
  removed_in: '3.0.0'
  why: Updated modules released with increased functionality
  alternative: cisco.meraki.networks_wireless_rf_profiles
options:
    state:
        description:
        - Query, edit, or delete wireless RF profile settings.
        type: str
        choices: [ present, query, absent]
        default: present
    net_name:
        description:
        - Name of network.
        type: str
    net_id:
        description:
        - ID of network.
        type: str
    profile_id:
        description:
        - Unique identifier of existing RF profile.
        type: str
        aliases: [ id ]
    band_selection_type:
        description:
        - Sets whether band selection is assigned per access point or SSID.
        - This param is required on creation.
        choices: [ ssid, ap ]
        type: str
    min_bitrate_type:
        description:
        - Type of minimum bitrate.
        choices: [ band, ssid ]
        type: str
    name:
        description:
        - The unique name of the new profile.
        - This param is required on creation.
        type: str
    client_balancing_enabled:
        description:
        - Steers client to best available access point.
        type: bool
    ap_band_settings:
        description:
        - Settings that will be enabled if selectionType is set to 'ap'.
        type: dict
        suboptions:
            mode:
                description:
                - Sets which RF band the AP will support.
                choices: [ 2.4ghz, 5ghz, dual ]
                aliases: [ band_operation_mode ]
                type: str
            band_steering_enabled:
                description:
                - Steers client to most open band.
                type: bool
    five_ghz_settings:
        description:
        - Settings related to 5Ghz band.
        type: dict
        suboptions:
            max_power:
                description:
                - Sets max power (dBm) of 5Ghz band.
                - Can be integer between 8 and 30.
                type: int
            min_power:
                description:
                - Sets minmimum power (dBm) of 5Ghz band.
                - Can be integer between 8 and 30.
                type: int
            min_bitrate:
                description:
                - Sets minimum bitrate (Mbps) of 5Ghz band.
                choices: [ 6, 9, 12, 18, 24, 36, 48, 54 ]
                type: int
            rxsop:
                description:
                - The RX-SOP level controls the sensitivity of the radio.
                - It is strongly recommended to use RX-SOP only after consulting a wireless expert.
                - RX-SOP can be configured in the range of -65 to -95 (dBm).
                type: int
            channel_width:
                description:
                - Sets channel width (MHz) for 5Ghz band.
                choices: [ auto, '20', '40', '80' ]
                type: str
            valid_auto_channels:
                description:
                - Sets valid auto channels for 5Ghz band.
                type: list
                elements: int
                choices: [36,
                          40,
                          44,
                          48,
                          52,
                          56,
                          60,
                          64,
                          100,
                          104,
                          108,
                          112,
                          116,
                          120,
                          124,
                          128,
                          132,
                          136,
                          140,
                          144,
                          149,
                          153,
                          157,
                          161,
                          165]
    two_four_ghz_settings:
        description:
        - Settings related to 2.4Ghz band
        type: dict
        suboptions:
            max_power:
                description:
                - Sets max power (dBm) of 2.4Ghz band.
                - Can be integer between 5 and 30.
                type: int
            min_power:
                description:
                - Sets minmimum power (dBm) of 2.4Ghz band.
                - Can be integer between 5 and 30.
                type: int
            min_bitrate:
                description:
                - Sets minimum bitrate (Mbps) of 2.4Ghz band.
                choices: [ 1, 2, 5.5, 6, 9, 11, 12, 18, 24, 36, 48, 54 ]
                type: float
            rxsop:
                description:
                - The RX-SOP level controls the sensitivity of the radio.
                - It is strongly recommended to use RX-SOP only after consulting a wireless expert.
                - RX-SOP can be configured in the range of -65 to -95 (dBm).
                type: int
            ax_enabled:
                description:
                - Determines whether ax radio on 2.4Ghz band is on or off.
                type: bool
            valid_auto_channels:
                description:
                - Sets valid auto channels for 2.4Ghz band.
                choices: [ 1, 6, 11 ]
                type: list
                elements: int
author:
- Kevin Breit (@kbreit)
extends_documentation_fragment: cisco.meraki.meraki
'''

EXAMPLES = r'''
- name: Create RF profile in check mode
  meraki_mr_rf_profile:
    auth_key: abc123
    org_name: YourOrg
    net_name: YourNet
    state: present
    name: Test Profile
    band_selection_type: ap
    client_balancing_enabled: true
    ap_band_settings:
      mode: dual
      band_steering_enabled: true
    five_ghz_settings:
      max_power: 10
      min_bitrate: 12
      min_power: 8
      rxsop: -65
      channel_width: 20
      valid_auto_channels:
        - 36
        - 40
        - 44
    two_four_ghz_settings:
      max_power: 10
      min_bitrate: 12
      min_power: 8
      rxsop: -65
      ax_enabled: false
      valid_auto_channels:
        - 1
  delegate_to: localhost

- name: Query all RF profiles
  meraki_mr_rf_profile:
    auth_key: abc123
    org_name: YourOrg
    net_name: YourNet
    state: query
  delegate_to: localhost

- name: Query one RF profile by ID
  meraki_mr_rf_profile:
    auth_key: abc123
    org_name: YourOrg
    net_name: YourNet
    state: query
    profile_id: '{{ profile_id }}'
  delegate_to: localhost

- name: Update profile
  meraki_mr_rf_profile:
    auth_key: abc123
    org_name: YourOrg
    net_name: YourNet
    state: present
    profile_id: 12345
    band_selection_type: ap
    client_balancing_enabled: true
    ap_band_settings:
      mode: dual
      band_steering_enabled: true
    five_ghz_settings:
      max_power: 10
      min_bitrate: 12
      min_power: 8
      rxsop: -65
      channel_width: 20
      valid_auto_channels:
        - 36
        - 44
    two_four_ghz_settings:
      max_power: 10
      min_bitrate: 12
      min_power: 8
      rxsop: -75
      ax_enabled: false
      valid_auto_channels:
        - 1
  delegate_to: localhost

- name: Delete RF profile
  meraki_mr_rf_profile:
    auth_key: abc123
    org_name: YourOrg
    net_name: YourNet
    state: absent
    profile_id: 12345
  delegate_to: localhost
'''

RETURN = r'''
data:
    description: List of wireless RF profile settings.
    returned: success
    type: complex
    contains:
        id:
            description:
            - Unique identifier of existing RF profile.
            type: str
            returned: success
            sample: 12345
        band_selection_type:
            description:
            - Sets whether band selection is assigned per access point or SSID.
            - This param is required on creation.
            type: str
            returned: success
            sample: ap
        min_bitrate_type:
            description:
            - Type of minimum bitrate.
            type: str
            returned: success
            sample: ssid
        name:
            description:
            - The unique name of the new profile.
            - This param is required on creation.
            type: str
            returned: success
            sample: Guest RF profile
        client_balancing_enabled:
            description:
            - Steers client to best available access point.
            type: bool
            returned: success
            sample: true
        ap_band_settings:
            description:
            - Settings that will be enabled if selectionType is set to 'ap'.
            type: complex
            returned: success
            contains:
                mode:
                    description:
                    - Sets which RF band the AP will support.
                    type: str
                    returned: success
                    sample: dual
                band_steering_enabled:
                    description:
                    - Steers client to most open band.
                    type: bool
                    returned: success
                    sample: true
        five_ghz_settings:
            description:
            - Settings related to 5Ghz band.
            type: complex
            returned: success
            contains:
                max_power:
                    description:
                    - Sets max power (dBm) of 5Ghz band.
                    - Can be integer between 8 and 30.
                    type: int
                    returned: success
                    sample: 12
                min_power:
                    description:
                    - Sets minmimum power (dBm) of 5Ghz band.
                    - Can be integer between 8 and 30.
                    type: int
                    returned: success
                    sample: 12
                min_bitrate:
                    description:
                    - Sets minimum bitrate (Mbps) of 5Ghz band.
                    type: int
                    returned: success
                    sample: 6
                rxsop:
                    description:
                    - The RX-SOP level controls the sensitivity of the radio.
                    type: int
                    returned: success
                    sample: -70
                channel_width:
                    description:
                    - Sets channel width (MHz) for 5Ghz band.
                    type: str
                    returned: success
                    sample: auto
                valid_auto_channels:
                    description:
                    - Sets valid auto channels for 5Ghz band.
                    type: list
                    returned: success
        two_four_ghz_settings:
            description:
            - Settings related to 2.4Ghz band
            type: complex
            returned: success
            contains:
                max_power:
                    description:
                    - Sets max power (dBm) of 2.4Ghz band.
                    type: int
                    returned: success
                    sample: 12
                min_power:
                    description:
                    - Sets minmimum power (dBm) of 2.4Ghz band.
                    type: int
                    returned: success
                    sample: 12
                min_bitrate:
                    description:
                    - Sets minimum bitrate (Mbps) of 2.4Ghz band.
                    type: float
                    returned: success
                    sample: 5.5
                rxsop:
                    description:
                    - The RX-SOP level controls the sensitivity of the radio.
                    type: int
                    returned: success
                    sample: -70
                ax_enabled:
                    description:
                    - Determines whether ax radio on 2.4Ghz band is on or off.
                    type: bool
                    returned: success
                    sample: true
                valid_auto_channels:
                    description:
                    - Sets valid auto channels for 2.4Ghz band.
                    type: list
                    returned: success
                    sample: 6
'''

from ansible.module_utils.basic import AnsibleModule, json
from ansible_collections.cisco.meraki.plugins.module_utils.network.meraki.meraki import MerakiModule, meraki_argument_spec


def get_profile(meraki, profiles, name):
    for profile in profiles:
        if profile['name'] == name:
            return profile
    return None


def construct_payload(meraki):
    payload = {}
    if meraki.params['name'] is not None:
        payload['name'] = meraki.params['name']
    if meraki.params['band_selection_type'] is not None:
        payload['bandSelectionType'] = meraki.params['band_selection_type']
    if meraki.params['min_bitrate_type'] is not None:
        payload['minBitrateType'] = meraki.params['min_bitrate_type']
    if meraki.params['client_balancing_enabled'] is not None:
        payload['clientBalancingEnabled'] = meraki.params['client_balancing_enabled']
    if meraki.params['ap_band_settings'] is not None:
        payload['apBandSettings'] = {}
        if meraki.params['ap_band_settings']['mode'] is not None:
            payload['apBandSettings']['bandOperationMode'] = meraki.params['ap_band_settings']['mode']
        if meraki.params['ap_band_settings']['band_steering_enabled'] is not None:
            payload['apBandSettings']['bandSteeringEnabled'] = meraki.params['ap_band_settings']['band_steering_enabled']
    if meraki.params['five_ghz_settings'] is not None:
        payload['fiveGhzSettings'] = {}
        if meraki.params['five_ghz_settings']['max_power'] is not None:
            payload['fiveGhzSettings']['maxPower'] = meraki.params['five_ghz_settings']['max_power']
        if meraki.params['five_ghz_settings']['min_bitrate'] is not None:
            payload['fiveGhzSettings']['minBitrate'] = meraki.params['five_ghz_settings']['min_bitrate']
        if meraki.params['five_ghz_settings']['min_power'] is not None:
            payload['fiveGhzSettings']['minPower'] = meraki.params['five_ghz_settings']['min_power']
        if meraki.params['five_ghz_settings']['rxsop'] is not None:
            payload['fiveGhzSettings']['rxsop'] = meraki.params['five_ghz_settings']['rxsop']
        if meraki.params['five_ghz_settings']['channel_width'] is not None:
            payload['fiveGhzSettings']['channelWidth'] = meraki.params['five_ghz_settings']['channel_width']
        if meraki.params['five_ghz_settings']['valid_auto_channels'] is not None:
            payload['fiveGhzSettings']['validAutoChannels'] = meraki.params['five_ghz_settings']['valid_auto_channels']
    if meraki.params['two_four_ghz_settings'] is not None:
        payload['twoFourGhzSettings'] = {}
        if meraki.params['two_four_ghz_settings']['max_power'] is not None:
            payload['twoFourGhzSettings']['maxPower'] = meraki.params['two_four_ghz_settings']['max_power']
        if meraki.params['two_four_ghz_settings']['min_bitrate'] is not None:
            payload['twoFourGhzSettings']['minBitrate'] = meraki.params['two_four_ghz_settings']['min_bitrate']
        if meraki.params['two_four_ghz_settings']['min_power'] is not None:
            payload['twoFourGhzSettings']['minPower'] = meraki.params['two_four_ghz_settings']['min_power']
        if meraki.params['two_four_ghz_settings']['rxsop'] is not None:
            payload['twoFourGhzSettings']['rxsop'] = meraki.params['two_four_ghz_settings']['rxsop']
        if meraki.params['two_four_ghz_settings']['ax_enabled'] is not None:
            payload['twoFourGhzSettings']['axEnabled'] = meraki.params['two_four_ghz_settings']['ax_enabled']
        if meraki.params['two_four_ghz_settings']['valid_auto_channels'] is not None:
            payload['twoFourGhzSettings']['validAutoChannels'] = meraki.params['two_four_ghz_settings']['valid_auto_channels']
    return payload


def main():
    # define the available arguments/parameters that a user can pass to
    # the module

    band_arg_spec = dict(mode=dict(type='str', aliases=['band_operation_mode'], choices=['2.4ghz', '5ghz', 'dual']),
                         band_steering_enabled=dict(type='bool'),
                         )

    five_arg_spec = dict(max_power=dict(type='int'),
                         min_bitrate=dict(type='int', choices=[6, 9, 12, 18, 24, 36, 48, 54]),
                         min_power=dict(type='int'),
                         rxsop=dict(type='int'),
                         channel_width=dict(type='str', choices=['auto', '20', '40', '80']),
                         valid_auto_channels=dict(type='list', elements='int', choices=[36,
                                                                                        40,
                                                                                        44,
                                                                                        48,
                                                                                        52,
                                                                                        56,
                                                                                        60,
                                                                                        64,
                                                                                        100,
                                                                                        104,
                                                                                        108,
                                                                                        112,
                                                                                        116,
                                                                                        120,
                                                                                        124,
                                                                                        128,
                                                                                        132,
                                                                                        136,
                                                                                        140,
                                                                                        144,
                                                                                        149,
                                                                                        153,
                                                                                        157,
                                                                                        161,
                                                                                        165]),
                         )

    two_arg_spec = dict(max_power=dict(type='int'),
                        min_bitrate=dict(type='float', choices=[1,
                                                                2,
                                                                5.5,
                                                                6,
                                                                9,
                                                                11,
                                                                12,
                                                                18,
                                                                24,
                                                                36,
                                                                48,
                                                                54]),
                        min_power=dict(type='int'),
                        rxsop=dict(type='int'),
                        ax_enabled=dict(type='bool'),
                        valid_auto_channels=dict(type='list', elements='int', choices=[1, 6, 11]),
                        )

    argument_spec = meraki_argument_spec()
    argument_spec.update(state=dict(type='str', choices=['present', 'query', 'absent'], default='present'),
                         org_name=dict(type='str', aliases=['organization']),
                         org_id=dict(type='str'),
                         net_name=dict(type='str'),
                         net_id=dict(type='str'),
                         profile_id=dict(type='str', aliases=['id']),
                         band_selection_type=dict(type='str', choices=['ssid', 'ap']),
                         min_bitrate_type=dict(type='str', choices=['band', 'ssid']),
                         name=dict(type='str'),
                         client_balancing_enabled=dict(type='bool'),
                         ap_band_settings=dict(type='dict', options=band_arg_spec),
                         five_ghz_settings=dict(type='dict', options=five_arg_spec),
                         two_four_ghz_settings=dict(type='dict', options=two_arg_spec),
                         )

    # the AnsibleModule object will be our abstraction working with Ansible
    # this includes instantiation, a couple of common attr would be the
    # args/params passed to the execution, as well as if the module
    # supports check mode
    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True,
                           )
    meraki = MerakiModule(module, function='mr_rf_profile')

    meraki.params['follow_redirects'] = 'all'

    query_all_urls = {'mr_rf_profile': '/networks/{net_id}/wireless/rfProfiles'}
    query_urls = {'mr_rf_profile': '/networks/{net_id}/wireless/rfProfiles/{profile_id}'}
    create_urls = {'mr_rf_profile': '/networks/{net_id}/wireless/rfProfiles'}
    update_urls = {'mr_rf_profile': '/networks/{net_id}/wireless/rfProfiles/{profile_id}'}
    delete_urls = {'mr_rf_profile': '/networks/{net_id}/wireless/rfProfiles/{profile_id}'}

    meraki.url_catalog['get_all'].update(query_all_urls)
    meraki.url_catalog['get_one'].update(query_urls)
    meraki.url_catalog['create'] = create_urls
    meraki.url_catalog['update'] = update_urls
    meraki.url_catalog['delete'] = delete_urls

    if meraki.params['five_ghz_settings'] is not None:
        if meraki.params['five_ghz_settings']['max_power'] is not None:
            if meraki.params['five_ghz_settings']['max_power'] < 8 or meraki.params['five_ghz_settings']['max_power'] > 30:
                meraki.fail_json(msg="5ghz max power must be between 8 and 30.")
        if meraki.params['five_ghz_settings']['min_power'] is not None:
            if meraki.params['five_ghz_settings']['min_power'] < 8 or meraki.params['five_ghz_settings']['min_power'] > 30:
                meraki.fail_json(msg="5ghz min power must be between 8 and 30.")
        if meraki.params['five_ghz_settings']['rxsop'] is not None:
            if meraki.params['five_ghz_settings']['rxsop'] < -95 or meraki.params['five_ghz_settings']['rxsop'] > -65:
                meraki.fail_json(msg="5ghz min power must be between 8 and 30.")
    if meraki.params['two_four_ghz_settings'] is not None:
        if meraki.params['two_four_ghz_settings']['max_power'] is not None:
            if meraki.params['two_four_ghz_settings']['max_power'] < 5 or meraki.params['two_four_ghz_settings']['max_power'] > 30:
                meraki.fail_json(msg="5ghz max power must be between 5 and 30.")
        if meraki.params['two_four_ghz_settings']['min_power'] is not None:
            if meraki.params['two_four_ghz_settings']['min_power'] < 5 or meraki.params['two_four_ghz_settings']['min_power'] > 30:
                meraki.fail_json(msg="5ghz min power must be between 5 and 30.")
        if meraki.params['two_four_ghz_settings']['rxsop'] is not None:
            if meraki.params['two_four_ghz_settings']['rxsop'] < -95 or meraki.params['two_four_ghz_settings']['rxsop'] > -65:
                meraki.fail_json(msg="5ghz min power must be between 8 and 30.")

    org_id = meraki.params['org_id']
    net_id = meraki.params['net_id']
    profile_id = meraki.params['profile_id']
    profile = None
    profiles = None
    if org_id is None:
        org_id = meraki.get_org_id(meraki.params['org_name'])
    if net_id is None:
        nets = meraki.get_nets(org_id=org_id)
        net_id = meraki.get_net_id(org_id, meraki.params['net_name'], data=nets)
    if profile_id is None:
        path = meraki.construct_path('get_all', net_id=net_id)
        profiles = meraki.request(path, method='GET')
        # profile = get_profile(meraki, profiles, meraki.params['name'])
        profile_id = next((profile['id'] for profile in profiles if profile['name'] == meraki.params['name']), None)

    if meraki.params['state'] == 'query':
        if profile_id is not None:
            path = meraki.construct_path('get_one', net_id=net_id, custom={'profile_id': profile_id})
            result = meraki.request(path, method='GET')
            meraki.result['data'] = result
            meraki.exit_json(**meraki.result)
        if profiles is None:
            path = meraki.construct_path('get_all', net_id=net_id)
            profiles = meraki.request(path, method='GET')
        meraki.result['data'] = profiles
        meraki.exit_json(**meraki.result)
    elif meraki.params['state'] == 'present':
        payload = construct_payload(meraki)
        if profile_id is None:  # Create a new RF profile
            if meraki.check_mode is True:
                meraki.result['data'] = payload
                meraki.result['changed'] = True
                meraki.exit_json(**meraki.result)
            path = meraki.construct_path('create', net_id=net_id)
            response = meraki.request(path, method='POST', payload=json.dumps(payload))
            meraki.result['data'] = response
            meraki.result['changed'] = True
            meraki.exit_json(**meraki.result)
        else:
            path = meraki.construct_path('get_one', net_id=net_id, custom={'profile_id': profile_id})
            original = meraki.request(path, method='GET')
            if meraki.is_update_required(original, payload) is True:
                if meraki.check_mode is True:
                    meraki.result['data'] = payload
                    meraki.result['changed'] = True
                    meraki.exit_json(**meraki.result)
                path = meraki.construct_path('update', net_id=net_id, custom={'profile_id': profile_id})
                response = meraki.request(path, method='PUT', payload=json.dumps(payload))
                meraki.result['data'] = response
                meraki.result['changed'] = True
                meraki.exit_json(**meraki.result)
            else:
                meraki.result['data'] = original
                meraki.exit_json(**meraki.result)
    elif meraki.params['state'] == 'absent':
        if meraki.check_mode is True:
            meraki.result['data'] = {}
            meraki.result['changed'] = True
            meraki.exit_json(**meraki.result)
        path = meraki.construct_path('delete', net_id=net_id, custom={'profile_id': profile_id})
        response = meraki.request(path, method='DELETE')
        meraki.result['data'] = {}
        meraki.result['changed'] = True
        meraki.exit_json(**meraki.result)

    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    meraki.exit_json(**meraki.result)


if __name__ == '__main__':
    main()
