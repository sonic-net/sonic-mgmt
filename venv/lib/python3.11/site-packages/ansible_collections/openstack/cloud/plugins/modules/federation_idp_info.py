#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
module: federation_idp_info
short_description: Fetch OpenStack federation identity providers
author: OpenStack Ansible SIG
description:
  - Fetch OpenStack federation identity providers.
options:
  id:
    description:
      - The ID (and name) of the identity provider to fetch.
    type: str
    aliases: ['name']
extends_documentation_fragment:
  - openstack.cloud.openstack
'''

EXAMPLES = r'''
- name: Fetch a specific identity provider
  openstack.cloud.federation_idp_info:
    cloud: example_cloud
    name: example_provider

- name: Fetch all providers
  openstack.cloud.federation_idp_info:
    cloud: example_cloud
'''

RETURN = r'''
identity_providers:
  description: Dictionary describing the identity providers
  returned: always
  type: list
  elements: dict
  contains:
    description:
      description: Identity provider description
      type: str
      sample: "demodescription"
    domain_id:
      description: Domain to which the identity provider belongs
      type: str
      sample: "default"
    id:
      description: Identity provider ID
      type: str
      sample: "test-idp"
    is_enabled:
      description: Indicates whether the identity provider is enabled
      type: bool
    name:
      description: Name of the identity provider, equals its ID.
      type: str
      sample: "test-idp"
    remote_ids:
      description: Remote IDs associated with the identity provider
      type: list
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import OpenStackModule


class IdentityFederationIdpInfoModule(OpenStackModule):
    argument_spec = dict(
        id=dict(aliases=['name']),
    )
    module_kwargs = dict(
        supports_check_mode=True
    )

    def run(self):
        kwargs = dict((k, self.params[k])
                      for k in ['id']
                      if self.params[k] is not None)
        identity_providers = self.conn.identity.identity_providers(**kwargs)
        self.exit_json(
            changed=False,
            identity_providers=[i.to_dict(computed=False)
                                for i in identity_providers])


def main():
    module = IdentityFederationIdpInfoModule()
    module()


if __name__ == '__main__':
    main()
