#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2019 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r"""
module: server
short_description: Update server information
version_added: 1.2.0
author:
  - Felix Fontein (@felixfontein)
description:
  - Allows to update server information.
  - Right now the API only supports updating the server's name.
extends_documentation_fragment:
  - community.hrobot.robot
  - community.hrobot.attributes
  - community.hrobot.attributes.actiongroup_robot

attributes:
  action_group:
    version_added: 1.6.0
  check_mode:
    support: full
  diff_mode:
    support: none
  idempotent:
    support: full

options:
  server_number:
    description:
      - The server number of the server to update.
    type: int
    required: true
  server_name:
    description:
      - The server's name.
      - If this option is not provided, it will not be adjusted.
    type: str
"""

EXAMPLES = r"""
---
- name: Set server's name to foo.example.com
  community.hrobot.server:
    hetzner_user: foo
    hetzner_password: bar
    server_number: 123
    server_name: foo.example.com
"""

RETURN = r"""
server:
  description:
    - Information on the server.
  returned: success
  type: dict
  contains:
    server_ip:
      description:
        - The server's main IP address.
      type: str
      sample: 123.123.123.123
      returned: success
    server_ipv6_net:
      description:
        - The server's main IPv6 network address.
      type: str
      sample: '2a01:f48:111:4221::'
      returned: success
    server_number:
      description:
        - The server's numeric ID.
      type: int
      sample: 321
      returned: success
    server_name:
      description:
        - The user-defined server's name.
      type: str
      sample: server1
      returned: success
    product:
      description:
        - The server product name.
      type: str
      sample: EQ 8
      returned: success
    dc:
      description:
        - The data center the server is located in.
      type: str
      sample: NBG1-DC1
      returned: success
    traffic:
      description:
        - Free traffic quota.
        - V(unlimited) in case of unlimited traffic.
      type: str
      sample: 5 TB
      returned: success
    status:
      description:
        - Server status.
      type: str
      choices:
        - ready
        - in process
      sample: ready
      returned: success
    cancelled:
      description:
        - Whether the server is cancelled.
      type: bool
      sample: false
      returned: success
    paid_until:
      description:
        - The date until the server has been paid.
      type: str
      sample: "2018-08-04"
      returned: success
    ip:
      description:
        - List of assigned single IP addresses.
      type: list
      elements: str
      sample:
        - 123.123.123.123
      returned: success
    subnet:
      description:
        - List of assigned subnets.
      type: list
      elements: dict
      sample:
        - ip: '2a01:4f8:111:4221::'
          mask: 64
      contains:
        ip:
          description:
            - The first IP in the subnet.
          type: str
          sample: '2a01:4f8:111:4221::'
        mask:
          description:
            - The masks bitlength.
          type: str
          sample: "64"
      returned: success
    reset:
      description:
        - Whether the server can be automatically reset.
      type: bool
      sample: true
      returned: success
    rescue:
      description:
        - Whether the rescue system is available.
      type: bool
      sample: false
      returned: success
    vnc:
      description:
        - Flag of VNC installation availability.
      type: bool
      sample: true
      returned: success
    windows:
      description:
        - Flag of Windows installation availability.
      type: bool
      sample: true
      returned: success
    plesk:
      description:
        - Flag of Plesk installation availability.
      type: bool
      sample: true
      returned: success
    cpanel:
      description:
        - Flag of cPanel installation availability.
      type: bool
      sample: true
      returned: success
    wol:
      description:
        - Flag of Wake On Lan availability.
      type: bool
      sample: true
      returned: success
    hot_swap:
      description:
        - Flag of Hot Swap availability.
      type: bool
      sample: true
      returned: success
    linked_storagebox:
      description:
        - Linked Storage Box ID.
      type: int
      sample: 12345
      returned: success
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.hrobot.plugins.module_utils.robot import (
    BASE_URL,
    ROBOT_DEFAULT_ARGUMENT_SPEC,
    fetch_url_json,
)

try:
    from urllib.parse import urlencode
except ImportError:
    # Python 2.x fallback:
    from urllib import urlencode


def main():
    argument_spec = dict(
        server_number=dict(type='int', required=True),
        server_name=dict(type='str'),
    )
    argument_spec.update(ROBOT_DEFAULT_ARGUMENT_SPEC)
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    server_number = module.params['server_number']
    server_name = module.params['server_name']

    url = "{0}/server/{1}".format(BASE_URL, server_number)
    server, error = fetch_url_json(module, url, accept_errors=['SERVER_NOT_FOUND'])
    if error:
        module.fail_json(msg='This server does not exist, or you do not have access rights for it')

    result = {
        'changed': False,
        'server': server['server'],
    }

    update = {}
    if server_name is not None:
        if server_name != result['server']['server_name']:
            update['server_name'] = server_name

    if update:
        result['changed'] = True
        if module.check_mode:
            result['server'].update(update)
        else:
            headers = {"Content-type": "application/x-www-form-urlencoded"}
            url = "{0}/server/{1}".format(BASE_URL, server_number)
            server, error = fetch_url_json(
                module,
                url,
                data=urlencode(update),
                headers=headers,
                method='POST',
                accept_errors=['INVALID_INPUT'],
            )
            if error:
                module.fail_json(msg='The values to update were invalid ({0})'.format(module.jsonify(update)))
            result['server'] = server['server']

    module.exit_json(**result)


if __name__ == '__main__':  # pragma: no cover
    main()  # pragma: no cover
