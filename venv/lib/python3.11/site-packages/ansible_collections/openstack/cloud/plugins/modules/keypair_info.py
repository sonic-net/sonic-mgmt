#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021 T-Systems International GmbH
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = '''
---
module: keypair_info
short_description: Get information about keypairs from OpenStack
author: OpenStack Ansible SIG
description:
  - Get information about keypairs that are associated with the account
options:
  name:
    description:
      - Name or ID of the keypair
    type: str
  user_id:
    description:
      - It allows admin users to operate key-pairs of specified user ID.
    type: str
  limit:
    description:
      - Requests a page size of items.
      - Returns a number of items up to a limit value.
    type: int
  marker:
    description:
      - The last-seen item.
    type: str
extends_documentation_fragment:
- openstack.cloud.openstack
'''

EXAMPLES = '''
- name: Get information about keypairs
  openstack.cloud.keypair_info:
  register: result

- name: Get information about keypairs using optional parameters
  openstack.cloud.keypair_info:
    name: "test"
    user_id: "fed75b36fd7a4078a769178d2b1bd844"
    limit: 10
    marker: "jdksl"
  register: result
'''

RETURN = '''
keypairs:
  description:
    - Lists keypairs that are associated with the account.
  type: list
  elements: dict
  returned: always
  contains:
    created_at:
      description:
        - The date and time when the resource was created.
      type: str
      sample: "2021-01-19T14:52:07.261634"
    id:
      description:
        - The id identifying the keypair
      type: str
      sample: "keypair-5d935425-31d5-48a7-a0f1-e76e9813f2c3"
    is_deleted:
      description:
        - A boolean indicates whether this keypair is deleted or not.
      type: bool
    fingerprint:
      description:
        - The fingerprint for the keypair.
      type: str
      sample: "7e:eb:ab:24:ba:d1:e1:88:ae:9a:fb:66:53:df:d3:bd"
    name:
      description:
        - A keypair name which will be used to reference it later.
      type: str
      sample: "keypair-5d935425-31d5-48a7-a0f1-e76e9813f2c3"
    private_key:
      description:
        - The private key for the keypair.
      type: str
      sample: "MIICXAIBAAKBgQCqGKukO ... hZj6+H0qtjTkVxwTCpvKe4eCZ0FPq"
    public_key:
      description:
        - The keypair public key.
      type: str
      sample: "ssh-rsa AAAAB3NzaC1yc ... 8rPsBUHNLQp Generated-by-Nova"
    type:
      description:
        - The type of the keypair.
        - Allowed values are ssh or x509.
      type: str
      sample: "ssh"
    user_id:
      description:
        - It allows admin users to operate key-pairs of specified user ID.
      type: str
      sample: "59b10f2a2138428ea9358e10c7e44444"
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import (
    OpenStackModule)


class KeyPairInfoModule(OpenStackModule):
    argument_spec = dict(
        name=dict(),
        user_id=dict(),
        limit=dict(type='int'),
        marker=dict()
    )
    module_kwargs = dict(
        supports_check_mode=True
    )

    def run(self):
        filters = {k: self.params[k] for k in
                   ['user_id', 'name', 'limit', 'marker']
                   if self.params[k] is not None}
        keypairs = self.conn.search_keypairs(name_or_id=self.params['name'],
                                             filters=filters)
        result = [raw.to_dict(computed=False) for raw in keypairs]
        self.exit(changed=False, keypairs=result)


def main():
    module = KeyPairInfoModule()
    module()


if __name__ == '__main__':
    main()
