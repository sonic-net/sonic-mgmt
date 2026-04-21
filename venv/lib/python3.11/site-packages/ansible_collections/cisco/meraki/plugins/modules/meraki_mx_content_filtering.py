#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2019, Kevin Breit (@kbreit) <kevin.breit@kevinbreit.net>
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
module: meraki_mx_content_filtering
short_description: Edit Meraki MX content filtering policies
description:
- Allows for setting policy on content filtering.
deprecated:
  removed_in: '3.0.0'
  why: Updated modules released with increased functionality
  alternative: cisco.meraki.networks_appliance_content_filtering
options:
    auth_key:
        description:
        - Authentication key provided by the dashboard. Required if environmental variable MERAKI_KEY is not set.
        type: str
    net_name:
        description:
        - Name of a network.
        aliases: [ network ]
        type: str
    net_id:
        description:
        - ID number of a network.
        type: str
    state:
        description:
        - States that a policy should be created or modified.
        choices: [present, query]
        default: present
        type: str
    allowed_urls:
        description:
        - List of URL patterns which should be allowed.
        type: list
        elements: str
    blocked_urls:
        description:
        - List of URL patterns which should be blocked.
        type: list
        elements: str
    blocked_categories:
        description:
        - List of content categories which should be blocked.
        - Use the C(meraki_content_filtering_facts) module for a full list of categories.
        type: list
        elements: str
    category_list_size:
        description:
        - Determines whether a network filters fo rall URLs in a category or only the list of top blocked sites.
        choices: [ top sites, full list ]
        type: str
    subset:
        description:
        - Display only certain facts.
        choices: [categories, policy]
        type: str
author:
    - Kevin Breit (@kbreit)
extends_documentation_fragment: cisco.meraki.meraki
'''

EXAMPLES = r'''
- name: Set single allowed URL pattern
  meraki_content_filtering:
    auth_key: abc123
    org_name: YourOrg
    net_name: YourMXNet
    allowed_urls:
      - "http://www.ansible.com/*"

- name: Set blocked URL category
  meraki_content_filtering:
    auth_key: abc123
    org_name: YourOrg
    net_name: YourMXNet
    state: present
    category_list_size: full list
    blocked_categories:
      - "Adult and Pornography"

- name: Remove match patterns and categories
  meraki_content_filtering:
    auth_key: abc123
    org_name: YourOrg
    net_name: YourMXNet
    state: present
    category_list_size: full list
    allowed_urls: []
    blocked_urls: []
'''

RETURN = r'''
data:
    description: Information about the created or manipulated object.
    returned: info
    type: complex
    contains:
      categories:
        description: List of available content filtering categories.
        returned: query for categories
        type: complex
        contains:
          id:
            description: Unique ID of content filtering category.
            returned: query for categories
            type: str
            sample: "meraki:contentFiltering/category/1"
          name:
            description: Name of content filtering category.
            returned: query for categories
            type: str
            sample: "Real Estate"
      allowed_url_patterns:
        description: Explicitly permitted URL patterns
        returned: query for policy
        type: list
        sample: ["http://www.ansible.com"]
      blocked_url_patterns:
        description: Explicitly denied URL patterns
        returned: query for policy
        type: list
        sample: ["http://www.ansible.net"]
      blocked_url_categories:
        description: List of blocked URL categories
        returned: query for policy
        type: complex
        contains:
          id:
            description: Unique ID of category to filter
            returned: query for policy
            type: list
            sample: ["meraki:contentFiltering/category/1"]
          name:
            description: Name of category to filter
            returned: query for policy
            type: list
            sample: ["Real Estate"]
      url_cateogory_list_size:
        description: Size of categories to cache on MX appliance
        returned: query for policy
        type: str
        sample: "topSites"
'''


from ansible.module_utils.basic import AnsibleModule, json
from ansible_collections.cisco.meraki.plugins.module_utils.network.meraki.meraki import MerakiModule, meraki_argument_spec, recursive_diff
from copy import deepcopy


def get_category_dict(meraki, full_list, category):
    for i in full_list['categories']:
        if i['name'] == category:
            return i['id']
    meraki.fail_json(msg="{0} is not a valid content filtering category".format(category))


def main():

    # define the available arguments/parameters that a user can pass to
    # the module
    path = ""
    argument_spec = meraki_argument_spec()
    argument_spec.update(
        net_id=dict(type='str'),
        net_name=dict(type='str', aliases=['network']),
        state=dict(type='str', default='present', choices=['present', 'query']),
        allowed_urls=dict(type='list', elements='str'),
        blocked_urls=dict(type='list', elements='str'),
        blocked_categories=dict(type='list', elements='str'),
        category_list_size=dict(type='str', choices=['top sites', 'full list']),
        subset=dict(type='str', choices=['categories', 'policy']),
    )

    # the AnsibleModule object will be our abstraction working with Ansible
    # this includes instantiation, a couple of common attr would be the
    # args/params passed to the execution, as well as if the module
    # supports check mode
    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True,
                           )

    meraki = MerakiModule(module, function='content_filtering')
    module.params['follow_redirects'] = 'all'

    category_urls = {'content_filtering': '/networks/{net_id}/appliance/contentFiltering/categories'}
    policy_urls = {'content_filtering': '/networks/{net_id}/appliance/contentFiltering'}

    meraki.url_catalog['categories'] = category_urls
    meraki.url_catalog['policy'] = policy_urls

    if meraki.params['net_name'] and meraki.params['net_id']:
        meraki.fail_json(msg='net_name and net_id are mutually exclusive')

    # manipulate or modify the state as needed (this is going to be the
    # part where your module will do what it needs to do)

    org_id = meraki.params['org_id']
    if not org_id:
        org_id = meraki.get_org_id(meraki.params['org_name'])
    net_id = None
    if net_id is None:
        nets = meraki.get_nets(org_id=org_id)
        net_id = meraki.get_net_id(org_id, meraki.params['net_name'], data=nets)

    if meraki.params['state'] == 'query':
        if meraki.params['subset']:
            if meraki.params['subset'] == 'categories':
                path = meraki.construct_path('categories', net_id=net_id)
            elif meraki.params['subset'] == 'policy':
                path = meraki.construct_path('policy', net_id=net_id)
            meraki.result['data'] = meraki.request(path, method='GET')
        else:
            response_data = {'categories': None,
                             'policy': None,
                             }
            path = meraki.construct_path('categories', net_id=net_id)
            response_data['categories'] = meraki.request(path, method='GET')
            path = meraki.construct_path('policy', net_id=net_id)
            response_data['policy'] = meraki.request(path, method='GET')
            meraki.result['data'] = response_data
    if module.params['state'] == 'present':
        payload = dict()
        if meraki.params['allowed_urls']:
            if meraki.params['allowed_urls'] == ['None']:  # Corner case for resetting
                payload['allowedUrlPatterns'] = []
            else:
                payload['allowedUrlPatterns'] = meraki.params['allowed_urls']
        if meraki.params['blocked_urls']:
            if meraki.params['blocked_urls'] == ['None']:  # Corner case for resetting
                payload['blockedUrlPatterns'] = []
            else:
                payload['blockedUrlPatterns'] = meraki.params['blocked_urls']
        if meraki.params['blocked_categories']:
            if meraki.params['blocked_categories'] == ['None']:  # Corner case for resetting
                payload['blockedUrlCategories'] = []
            else:
                category_path = meraki.construct_path('categories', net_id=net_id)
                categories = meraki.request(category_path, method='GET')
                payload['blockedUrlCategories'] = []
                for category in meraki.params['blocked_categories']:
                    payload['blockedUrlCategories'].append(get_category_dict(meraki,
                                                                             categories,
                                                                             category))
        if meraki.params['category_list_size']:
            if meraki.params['category_list_size'].lower() == 'top sites':
                payload['urlCategoryListSize'] = "topSites"
            elif meraki.params['category_list_size'].lower() == 'full list':
                payload['urlCategoryListSize'] = "fullList"
        path = meraki.construct_path('policy', net_id=net_id)
        current = meraki.request(path, method='GET')
        proposed = current.copy()
        proposed.update(payload)
        temp_current = deepcopy(current)
        temp_blocked = []
        for blocked_category in current['blockedUrlCategories']:
            temp_blocked.append(blocked_category['id'])
        temp_current.pop('blockedUrlCategories')
        if 'blockedUrlCategories' in payload:
            payload['blockedUrlCategories'].sort()
        temp_current['blockedUrlCategories'] = temp_blocked
        if meraki.is_update_required(temp_current, payload) is True:
            if module.check_mode:
                meraki.generate_diff(current, payload)
                current.update(payload)
                meraki.result['changed'] = True
                meraki.result['data'] = current
                meraki.exit_json(**meraki.result)
            response = meraki.request(path, method='PUT', payload=json.dumps(payload))
            meraki.result['data'] = response
            if recursive_diff(current, response) is None:
                meraki.result['changed'] = False
                meraki.result['data'] = str(recursive_diff(current, response))
            else:
                meraki.result['changed'] = True
                meraki.generate_diff(current, response)
        else:
            meraki.result['data'] = current
            if module.check_mode:
                meraki.result['data'] = current
                meraki.exit_json(**meraki.result)
            meraki.result['data'] = current
            meraki.exit_json(**meraki.result)

    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    meraki.exit_json(**meraki.result)


if __name__ == '__main__':
    main()
