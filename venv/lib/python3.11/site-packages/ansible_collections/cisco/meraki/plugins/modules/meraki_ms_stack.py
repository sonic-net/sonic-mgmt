#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Kevin Breit (@kbreit) <kevin.breit@kevinbreit.net>
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
module: meraki_ms_stack
short_description: Modify switch stacking configuration in Meraki.
version_added: "1.3.0"
description:
- Allows for modification of Meraki MS switch stacks.
notes:
- Not all actions are idempotent. Specifically, creating a new stack will error if any switch is already in a stack.
deprecated:
  removed_in: '3.0.0'
  why: Updated modules released with increased functionality
  alternative: cisco.meraki.networks_switch_stacks
options:
    state:
        description:
        - Create or modify an organization.
        choices: ['present', 'query', 'absent']
        default: present
        type: str
    net_name:
        description:
        - Name of network which MX firewall is in.
        type: str
    net_id:
        description:
        - ID of network which MX firewall is in.
        type: str
    stack_id:
        description:
        - ID of stack which is to be modified or deleted.
        type: str
    serials:
        description:
        - List of switch serial numbers which should be included or removed from a stack.
        type: list
        elements: str
    name:
        description:
        - Name of stack.
        type: str

author:
- Kevin Breit (@kbreit)
extends_documentation_fragment: cisco.meraki.meraki
'''

EXAMPLES = r'''
- name: Create new stack
  meraki_switch_stack:
    auth_key: abc123
    state: present
    org_name: YourOrg
    net_name: YourNet
    name: Test stack
    serials:
      - "ABCD-1231-4579"
      - "ASDF-4321-0987"

- name: Add switch to stack
  meraki_switch_stack:
    auth_key: abc123
    state: present
    org_name: YourOrg
    net_name: YourNet
    stack_id: ABC12340987
    serials:
      - "ABCD-1231-4579"

- name: Remove switch from stack
  meraki_switch_stack:
    auth_key: abc123
    state: absent
    org_name: YourOrg
    net_name: YourNet
    stack_id: ABC12340987
    serials:
      - "ABCD-1231-4579"

- name: Query one stack
  meraki_switch_stack:
    auth_key: abc123
    state: query
    org_name: YourOrg
    net_name: YourNet
    stack_id: ABC12340987
'''

RETURN = r'''
data:
    description: VPN settings.
    returned: success
    type: complex
    contains:
        id:
          description: ID of switch stack.
          returned: always
          type: str
          sample: 7636
        name:
          description: Descriptive name of switch stack.
          returned: always
          type: str
          sample: MyStack
        serials:
            description: List of serial numbers in switch stack.
            returned: always
            type: list
            sample:
              - "QBZY-XWVU-TSRQ"
              - "QBAB-CDEF-GHIJ"
'''

from ansible.module_utils.basic import AnsibleModule, json
from ansible_collections.cisco.meraki.plugins.module_utils.network.meraki.meraki import MerakiModule, meraki_argument_spec
from copy import deepcopy


def get_stacks(meraki, net_id):
    path = meraki.construct_path('get_all', net_id=net_id)
    return meraki.request(path, method='GET')


def get_stack(stack_id, stacks):
    for stack in stacks:
        if stack_id == stack['id']:
            return stack
    return None


def get_stack_id(meraki, net_id):
    stacks = get_stacks(meraki, net_id)
    for stack in stacks:
        if stack['name'] == meraki.params['name']:
            return stack['id']


def does_stack_exist(meraki, stacks):
    for stack in stacks:
        have = set(meraki.params['serials'])
        want = set(stack['serials'])
        if have == want:
            return stack
    return False


def main():
    # define the available arguments/parameters that a user can pass to
    # the module

    argument_spec = meraki_argument_spec()
    argument_spec.update(state=dict(type='str', choices=['present', 'query', 'absent'], default='present'),
                         net_name=dict(type='str'),
                         net_id=dict(type='str'),
                         stack_id=dict(type='str'),
                         serials=dict(type='list', elements='str', default=None),
                         name=dict(type='str'),
                         )

    # the AnsibleModule object will be our abstraction working with Ansible
    # this includes instantiation, a couple of common attr would be the
    # args/params passed to the execution, as well as if the module
    # supports check mode
    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True,
                           )
    meraki = MerakiModule(module, function='switch_stack')

    meraki.params['follow_redirects'] = 'all'

    query_urls = {'switch_stack': '/networks/{net_id}/switch/stacks'}
    query_url = {'switch_stack': '/networks/{net_id}/switch/stacks/{stack_id}'}
    add_urls = {'switch_stack': '/networks/{net_id}/switch/stacks/{stack_id}/add'}
    remove_urls = {'switch_stack': '/networks/{net_id}/switch/stacks/{stack_id}/remove'}
    create_urls = {'switch_stack': '/networks/{net_id}/switch/stacks'}
    delete_urls = {'switch_stack': '/networks/{net_id}/switch/stacks/{stack_id}'}

    meraki.url_catalog['get_all'].update(query_urls)
    meraki.url_catalog['get_one'].update(query_url)
    meraki.url_catalog['add'] = add_urls
    meraki.url_catalog['remove'] = remove_urls
    meraki.url_catalog['create'] = create_urls
    meraki.url_catalog['delete'] = delete_urls

    payload = None

    # manipulate or modify the state as needed (this is going to be the
    # part where your module will do what it needs to do)
    org_id = meraki.params['org_id']
    if org_id is None:
        orgs = meraki.get_orgs()
        for org in orgs:
            if org['name'] == meraki.params['org_name']:
                org_id = org['id']
    net_id = meraki.params['net_id']
    if net_id is None:
        net_id = meraki.get_net_id(net_name=meraki.params['net_name'],
                                   data=meraki.get_nets(org_id=org_id))

    # assign and lookup stack_id
    stack_id = meraki.params['stack_id']
    if stack_id is None and meraki.params['name'] is not None:
        stack_id = get_stack_id(meraki, net_id)
    path = meraki.construct_path('get_all', net_id=net_id)
    stacks = meraki.request(path, method='GET')

    if meraki.params['state'] == 'query':
        if stack_id is None:
            meraki.result['data'] = stacks
        else:
            meraki.result['data'] = get_stack(stack_id, stacks)
    elif meraki.params['state'] == 'present':
        if meraki.params['stack_id'] is None:
            payload = {'serials': meraki.params['serials'],
                       'name': meraki.params['name'],
                       }
            path = meraki.construct_path('create', net_id=net_id)
            response = meraki.request(path, method='POST', payload=json.dumps(payload))
            if meraki.status == 201:
                meraki.result['data'] = response
                meraki.result['changed'] = True
        else:
            payload = {'serial': meraki.params['serials'][0]}
            original = get_stack(stack_id, stacks)
            comparable = deepcopy(original)
            comparable.update(payload)
            if meraki.params['serials'][0] not in comparable['serials']:
                comparable['serials'].append(meraki.params['serials'][0])
            # meraki.fail_json(msg=comparable)
            if meraki.is_update_required(original, comparable, optional_ignore=['serial']):
                path = meraki.construct_path('add', net_id=net_id, custom={'stack_id': stack_id})
                response = meraki.request(path, method='POST', payload=json.dumps(payload))
                if meraki.status == 200:
                    meraki.result['data'] = response
                    meraki.result['changed'] = True
            else:
                meraki.result['data'] = original
    elif meraki.params['state'] == 'absent':
        if meraki.params['serials'] is None:
            path = meraki.construct_path('delete', net_id=net_id, custom={'stack_id': stack_id})
            response = meraki.request(path, method='DELETE')
            meraki.result['data'] = {}
            meraki.result['changed'] = True
        else:
            for serial in meraki.params['serials']:
                payload = {'serial': serial}
                original = get_stack(stack_id, stacks)
                comparable = deepcopy(original)
                comparable.update(payload)
                if serial in comparable['serials']:
                    comparable['serials'].remove(serial)
                if meraki.is_update_required(original, comparable, optional_ignore=['serial']):
                    path = meraki.construct_path('remove', net_id=net_id, custom={'stack_id': stack_id})
                    response = meraki.request(path, method='POST', payload=json.dumps(payload))
                    if meraki.status == 200:
                        meraki.result['data'] = response
                        meraki.result['changed'] = True
                else:
                    meraki.result['data'] = original

    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    meraki.exit_json(**meraki.result)


if __name__ == '__main__':
    main()
