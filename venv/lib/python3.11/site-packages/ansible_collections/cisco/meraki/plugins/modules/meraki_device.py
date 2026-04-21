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
module: meraki_device
short_description: Manage devices in the Meraki cloud
description:
- Visibility into devices associated to a Meraki environment.
notes:
- This module does not support claiming of devices or licenses into a Meraki organization.
- More information about the Meraki API can be found at U(https://dashboard.meraki.com/api_docs).
- Some of the options are likely only used for developers within Meraki.
deprecated:
  removed_in: '3.0.0'
  why: Updated modules released with increased functionality
  alternative: cisco.meraki.networks_devices_claim, cisco.meraki.networks_devices_remove and cisco.meraki.networks
options:
    state:
        description:
        - Query an organization.
        choices: [absent, present, query]
        default: query
        type: str
    net_name:
        description:
        - Name of a network.
        aliases: [network]
        type: str
    net_id:
        description:
        - ID of a network.
        type: str
    serial:
        description:
        - Serial number of a device to query.
        type: str
    hostname:
        description:
        - Hostname of network device to search for.
        aliases: [name]
        type: str
    model:
        description:
        - Model of network device to search for.
        type: str
    tags:
        description:
        - Space delimited list of tags to assign to device.
        type: list
        elements: str
    lat:
        description:
        - Latitude of device's geographic location.
        - Use negative number for southern hemisphere.
        aliases: [latitude]
        type: float
    lng:
        description:
        - Longitude of device's geographic location.
        - Use negative number for western hemisphere.
        aliases: [longitude]
        type: float
    address:
        description:
        - Postal address of device's location.
        type: str
    move_map_marker:
        description:
        - Whether or not to set the latitude and longitude of a device based on the new address.
        - Only applies when C(lat) and C(lng) are not specified.
        type: bool
    lldp_cdp_timespan:
        description:
        - Timespan, in seconds, used to query LLDP and CDP information.
        - Must be less than 1 month.
        type: int
    note:
        description:
        - Informational notes about a device.
        - Limited to 255 characters.
        type: str
    query:
        description:
        - Specifies what information should be queried.
        type: str
        choices: [lldp_cdp, uplink]


author:
- Kevin Breit (@kbreit)
extends_documentation_fragment: cisco.meraki.meraki
'''

EXAMPLES = r'''
- name: Query all devices in an organization.
  meraki_device:
    auth_key: abc12345
    org_name: YourOrg
    state: query
  delegate_to: localhost

- name: Query all devices in a network.
  meraki_device:
    auth_key: abc12345
    org_name: YourOrg
    net_name: YourNet
    state: query
  delegate_to: localhost

- name: Query a device by serial number.
  meraki_device:
    auth_key: abc12345
    org_name: YourOrg
    net_name: YourNet
    serial: ABC-123
    state: query
  delegate_to: localhost

- name: Lookup uplink information about a device.
  meraki_device:
    auth_key: abc12345
    org_name: YourOrg
    net_name: YourNet
    serial_uplink: ABC-123
    state: query
  delegate_to: localhost

- name: Lookup LLDP and CDP information about devices connected to specified device.
  meraki_device:
    auth_key: abc12345
    org_name: YourOrg
    net_name: YourNet
    serial_lldp_cdp: ABC-123
    state: query
  delegate_to: localhost

- name: Lookup a device by hostname.
  meraki_device:
    auth_key: abc12345
    org_name: YourOrg
    net_name: YourNet
    hostname: main-switch
    state: query
  delegate_to: localhost

- name: Query all devices of a specific model.
  meraki_device:
    auth_key: abc123
    org_name: YourOrg
    net_name: YourNet
    model: MR26
    state: query
  delegate_to: localhost

- name: Update information about a device.
  meraki_device:
    auth_key: abc123
    org_name: YourOrg
    net_name: YourNet
    state: present
    serial: '{{ serial }}'
    name: mr26
    address: 1060 W. Addison St., Chicago, IL
    lat: 41.948038
    lng: -87.65568
    tags: recently-added
  delegate_to: localhost

- name: Claim a device into a network.
  meraki_device:
    auth_key: abc123
    org_name: YourOrg
    net_name: YourNet
    serial: ABC-123
    state: present
  delegate_to: localhost

- name: Remove a device from a network.
  meraki_device:
    auth_key: abc123
    org_name: YourOrg
    net_name: YourNet
    serial: ABC-123
    state: absent
  delegate_to: localhost
'''

RETURN = r'''
response:
    description: Data returned from Meraki dashboard.
    type: dict
    returned: info
'''

from ansible.module_utils.basic import AnsibleModule, json
from ansible_collections.cisco.meraki.plugins.module_utils.network.meraki.meraki import MerakiModule, meraki_argument_spec


def is_device_valid(meraki, serial, data):
    """ Parse a list of devices for a serial and return True if it's in the list """
    for device in data:
        if device['serial'] == serial:
            return True
    return False


def get_org_devices(meraki, org_id):
    """ Get all devices in an organization """
    path = meraki.construct_path('get_all_org', org_id=org_id)
    response = meraki.request(path, method='GET')
    if meraki.status != 200:
        meraki.fail_json(msg='Failed to query all devices belonging to the organization')
    return response


def get_net_devices(meraki, net_id):
    """ Get all devices in a network """
    path = meraki.construct_path('get_all', net_id=net_id)
    response = meraki.request(path, method='GET')
    if meraki.status != 200:
        meraki.fail_json(msg='Failed to query all devices belonging to the network')
    return response


def construct_payload(params):
    """ Create payload based on inputs """
    payload = {}
    if params['hostname'] is not None:
        payload['name'] = params['hostname']
    if params['tags'] is not None:
        payload['tags'] = params['tags']
    if params['lat'] is not None:
        payload['lat'] = params['lat']
    if params['lng'] is not None:
        payload['lng'] = params['lng']
    if params['address'] is not None:
        payload['address'] = params['address']
    if params['move_map_marker'] is not None:
        payload['moveMapMarker'] = params['move_map_marker']
    if params['note'] is not None:
        payload['notes'] = params['note']
    return payload


def main():

    # define the available arguments/parameters that a user can pass to
    # the module
    argument_spec = meraki_argument_spec()
    argument_spec.update(state=dict(type='str', choices=['absent', 'present', 'query'], default='query'),
                         net_name=dict(type='str', aliases=['network']),
                         net_id=dict(type='str'),
                         serial=dict(type='str'),
                         lldp_cdp_timespan=dict(type='int'),
                         hostname=dict(type='str', aliases=['name']),
                         model=dict(type='str'),
                         tags=dict(type='list', elements='str', default=None),
                         lat=dict(type='float', aliases=['latitude'], default=None),
                         lng=dict(type='float', aliases=['longitude'], default=None),
                         address=dict(type='str', default=None),
                         move_map_marker=dict(type='bool', default=None),
                         note=dict(type='str', default=None),
                         query=dict(type='str', default=None, choices=['lldp_cdp', 'uplink'])
                         )

    # the AnsibleModule object will be our abstraction working with Ansible
    # this includes instantiation, a couple of common attr would be the
    # args/params passed to the execution, as well as if the module
    # supports check mode
    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=False,
                           )
    meraki = MerakiModule(module, function='device')

    if meraki.params['query'] is not None \
       and meraki.params['query'] == 'lldp_cdp' \
       and not meraki.params['lldp_cdp_timespan']:
        meraki.fail_json(msg='lldp_cdp_timespan is required when querying LLDP and CDP information')
    if meraki.params['net_name'] and meraki.params['net_id']:
        meraki.fail_json(msg='net_name and net_id are mutually exclusive')

    meraki.params['follow_redirects'] = 'all'

    query_urls = {'device': '/networks/{net_id}/devices'}
    query_org_urls = {'device': '/organizations/{org_id}/devices'}
    query_device_urls = {'device': '/devices/{serial}'}
    query_device_lldp_urls = {'device': '/devices/{serial}/lldpCdp'}
    claim_device_urls = {'device': '/networks/{net_id}/devices/claim'}
    bind_org_urls = {'device': '/organizations/{org_id}/claim'}
    update_device_urls = {'device': '/devices/{serial}'}
    delete_device_urls = {'device': '/networks/{net_id}/devices/remove'}

    meraki.url_catalog['get_all'].update(query_urls)
    meraki.url_catalog['get_all_org'] = query_org_urls
    meraki.url_catalog['get_device'] = query_device_urls
    meraki.url_catalog['get_device_uplink'] = query_device_urls
    meraki.url_catalog['get_device_lldp'] = query_device_lldp_urls
    meraki.url_catalog['create'] = claim_device_urls
    meraki.url_catalog['bind_org'] = bind_org_urls
    meraki.url_catalog['update'] = update_device_urls
    meraki.url_catalog['delete'] = delete_device_urls

    payload = None

    # execute checks for argument completeness

    # manipulate or modify the state as needed (this is going to be the
    # part where your module will do what it needs to do)
    org_id = meraki.params['org_id']
    if org_id is None:
        org_id = meraki.get_org_id(meraki.params['org_name'])
    nets = meraki.get_nets(org_id=org_id)
    net_id = None
    if meraki.params['net_id'] or meraki.params['net_name']:
        net_id = meraki.params['net_id']
        if net_id is None:
            net_id = meraki.get_net_id(net_name=meraki.params['net_name'], data=nets)

    if meraki.params['state'] == 'query':
        if meraki.params['net_name'] or meraki.params['net_id']:
            device = []
            if meraki.params['serial']:
                path = meraki.construct_path('get_device', net_id=net_id, custom={'serial': meraki.params['serial']})
                request = meraki.request(path, method='GET')
                device.append(request)
                meraki.result['data'] = device
                if meraki.params['query'] == 'uplink':
                    path = meraki.construct_path('get_device_uplink', net_id=net_id, custom={'serial': meraki.params['serial']})
                    meraki.result['data'] = (meraki.request(path, method='GET'))
                elif meraki.params['query'] == 'lldp_cdp':
                    if meraki.params['lldp_cdp_timespan'] > 2592000:
                        meraki.fail_json(msg='LLDP/CDP timespan must be less than a month (2592000 seconds)')
                    path = meraki.construct_path('get_device_lldp', net_id=net_id, custom={'serial': meraki.params['serial']})
                    path = path + '?timespan=' + str(meraki.params['lldp_cdp_timespan'])
                    device.append(meraki.request(path, method='GET'))
                    meraki.result['data'] = device
            elif meraki.params['hostname']:
                path = meraki.construct_path('get_all', net_id=net_id)
                devices = meraki.request(path, method='GET')
                for unit in devices:
                    try:
                        if unit['name'] == meraki.params['hostname']:
                            device.append(unit)
                            meraki.result['data'] = device
                    except KeyError:
                        pass
            elif meraki.params['model']:
                path = meraki.construct_path('get_all', net_id=net_id)
                devices = meraki.request(path, method='GET')
                device_match = []
                for device in devices:
                    if device['model'] == meraki.params['model']:
                        device_match.append(device)
                meraki.result['data'] = device_match
            else:
                path = meraki.construct_path('get_all', net_id=net_id)
                request = meraki.request(path, method='GET')
                meraki.result['data'] = request
        else:
            path = meraki.construct_path('get_all_org', org_id=org_id, params={'perPage': '1000'})
            devices = meraki.request(path, method='GET', pagination_items=1000)
            if meraki.params['serial']:
                for device in devices:
                    if device['serial'] == meraki.params['serial']:
                        meraki.result['data'] = device
            else:
                meraki.result['data'] = devices
    elif meraki.params['state'] == 'present':
        device = []
        if net_id is None:  # Claim a device to an organization
            device_list = get_org_devices(meraki, org_id)
            if is_device_valid(meraki, meraki.params['serial'], device_list) is False:
                payload = {'serial': meraki.params['serial']}
                path = meraki.construct_path('bind_org', org_id=org_id)
                created_device = []
                created_device.append(meraki.request(path, method='POST', payload=json.dumps(payload)))
                meraki.result['data'] = created_device
                meraki.result['changed'] = True
        else:  # A device is assumed to be in an organization
            device_list = get_net_devices(meraki, net_id)
            if is_device_valid(meraki, meraki.params['serial'], device_list) is True:  # Device is in network, update
                query_path = meraki.construct_path('get_all', net_id=net_id)
                if is_device_valid(meraki, meraki.params['serial'], device_list):
                    payload = construct_payload(meraki.params)
                    query_path = meraki.construct_path('get_device', net_id=net_id, custom={'serial': meraki.params['serial']})
                    device_data = meraki.request(query_path, method='GET')
                    ignore_keys = ['lanIp', 'serial', 'mac', 'model', 'networkId', 'moveMapMarker', 'wan1Ip', 'wan2Ip']
                    if meraki.is_update_required(device_data, payload, optional_ignore=ignore_keys):
                        path = meraki.construct_path('update', custom={'serial': meraki.params['serial']})
                        updated_device = []
                        updated_device.append(meraki.request(path, method='PUT', payload=json.dumps(payload)))
                        meraki.result['data'] = updated_device
                        meraki.result['changed'] = True
                    else:
                        meraki.result['data'] = device_data
            else:  # Claim device into network
                query_path = meraki.construct_path('get_all', net_id=net_id)
                device_list = meraki.request(query_path, method='GET')
                if is_device_valid(meraki, meraki.params['serial'], device_list) is False:
                    if net_id:
                        payload = {'serials': [meraki.params['serial']]}
                        path = meraki.construct_path('create', net_id=net_id)
                        created_device = []
                        created_device.append(meraki.request(path, method='POST', payload=json.dumps(payload)))
                        meraki.result['data'] = created_device
                        meraki.result['changed'] = True
    elif meraki.params['state'] == 'absent':
        device = []
        query_path = meraki.construct_path('get_all', net_id=net_id)
        device_list = meraki.request(query_path, method='GET')
        if is_device_valid(meraki, meraki.params['serial'], device_list) is True:
            payload = {'serial': meraki.params['serial']}
            path = meraki.construct_path('delete', net_id=net_id)
            request = meraki.request(path, method='POST', payload=json.dumps(payload))
            meraki.result['changed'] = True

    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    meraki.exit_json(**meraki.result)


if __name__ == '__main__':
    main()
