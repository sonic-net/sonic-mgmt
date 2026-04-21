#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2015 Hewlett-Packard Development Company, L.P.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: auth
short_description: Retrieve auth token from OpenStack cloud
author: OpenStack Ansible SIG
description:
    - Retrieve auth token from OpenStack cloud
extends_documentation_fragment:
- openstack.cloud.openstack
'''

EXAMPLES = r'''
- name: Authenticate to cloud and return auth token
  openstack.cloud.auth:
    cloud: rax-dfw
'''

RETURN = r'''
auth_token:
    description: Openstack API Auth Token
    returned: success
    type: str
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import OpenStackModule


class AuthModule(OpenStackModule):
    def run(self):
        self.exit_json(changed=False,
                       auth_token=self.conn.auth_token)


def main():
    module = AuthModule()
    module()


if __name__ == '__main__':
    main()
