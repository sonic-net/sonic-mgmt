#!/usr/bin/python
#
# (c) 2015 Peter Sprygada, <psprygada@ansible.com>
# Copyright (c) 2025 Dell Inc.
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_vlans
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
---
module: sonic_api
version_added: 1.0.0
notes:
- Tested against Enterprise SONiC Distribution by Dell Technologies.
- Supports C(check_mode).
author: Abirami N (@abirami-n)
short_description: Manages REST operations on devices running Enterprise SONiC
description:
  - Manages REST operations on devices running Enterprise SONiC Distribution
    by Dell Technologies. This module provides an implementation for working
    with SONiC REST operations in a deterministic way.
options:
  url:
    description:
      - The HTTP path of the request after 'restconf/'.
    type: path
    required: true
  body:
    description:
      - The body of the HTTP request/response to the web service which contains the payload.
    type: raw
  method:
    description:
      - The HTTP method of the request or response. Must be a valid method
        accepted by the service that handles the request.
    type: str
    required: true
    choices: ['GET', 'PUT', 'POST', 'PATCH', 'DELETE']
  status_code:
    description:
      - A list of valid, numeric, HTTP status codes that signifies the success of a request.
    type: list
    elements: int
    required: true
"""

EXAMPLES = """
- name: Checks that you can connect (GET) to a page and it returns a status 200
  dellemc.enterprise_sonic.sonic_api:
    url: data/openconfig-interfaces:interfaces/interface=Ethernet60
    method: "GET"
    status_code: 200

- name: Appends data to an existing interface using PATCH and verifies if it returns status 204
  dellemc.enterprise_sonic.sonic_api:
    url: data/openconfig-interfaces:interfaces/interface=Ethernet60/config/description
    method: "PATCH"
    body: {"openconfig-interfaces:description": "Eth-60"}
    status_code: 204

- name: Deletes an associated IP address using DELETE and verifies if it returns status 204
  dellemc.enterprise_sonic.sonic_api:
    url: >
      data/openconfig-interfaces:interfaces/interface=Ethernet64/subinterfaces/subinterface=0/
      openconfig-if-ip:ipv4/addresses/address=1.1.1.1/config/prefix-length
    method: "DELETE"
    status_code: 204

- name: Adds a VLAN network instance using PUT and verifies if it returns status 204
  dellemc.enterprise_sonic.sonic_api:
    url: data/openconfig-network-instance:network-instances/network-instance=Vlan100/
    method: "PUT"
    body: {"openconfig-network-instance:network-instance": [{"name": "Vlan100", "config": {"name": "Vlan100"}}]}
    status_code: 204

- name: Adds a prefix-set to a routing policy using POST and verifies if it returns 201
  dellemc.enterprise_sonic.sonic_api:
    url: data/openconfig-routing-policy:routing-policy/defined-sets/prefix-sets/prefix-set=p1
    method: "POST"
    body: {"openconfig-routing-policy:config": {"name": "p1", "mode": "IPV4" }}
    status_code: 201
"""

RETURN = """
response:
  description: The response at the network device end for the REST call which contains the status code.
  returned: always
  type: list
  sample: {"response": [ 204,{""}]}
msg:
  description: The HTTP error message from the request.
  returned: HTTP Error
  type: str
"""

from ansible.module_utils.connection import ConnectionError

from ansible.module_utils._text import to_text
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import edit_config, to_request


def initiate_request(module):
    """
    Get all the data available in the chassis.
    """
    url = module.params['url']
    body = module.params['body']
    method = module.params['method']
    if method == "GET" or method == "DELETE":
        request = to_request(module, [{"path": url, "method": method}])
    elif method == "PATCH" or method == "PUT" or method == "POST":
        request = to_request(module, [{"path": url, "method": method, "data": body}])

    try:
        response = edit_config(module, request, suppr_ntf_excp=False)
    except ConnectionError as exc:
        module.fail_json(msg=to_text(exc))
    return response


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    argument_spec = dict(
        url=dict(type='path', required=True),
        body=dict(type='raw', required=False),
        method=dict(type='str', choices=['GET', 'PUT', 'PATCH', 'DELETE', 'POST'], required=True),
        status_code=dict(type='list', elements='int', required=True),
    )

    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True)

    result = dict(
        changed=False,
    )
    response = initiate_request(module)
    response_code = response[0][0]
    status_code = module.params['status_code']
    if response_code == int(status_code[0]) and response_code in (201, 204):
        result.update({'changed': True})

    result.update({
        'response': response,
    })
    module.exit_json(**result)


if __name__ == '__main__':
    main()
