#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
module: federation_idp
short_description: Manage an identity provider in a OpenStack cloud
author: OpenStack Ansible SIG
description:
  - Create, update or delete an identity provider of the OpenStack
    identity (Keystone) service.
options:
  description:
    description:
      - The description of the identity provider.
    type: str
  domain_id:
    description:
      - The ID of a domain that is associated with the identity provider.
      - Federated users that authenticate with the identity provider will be
        created under the domain specified.
      - Required when creating a new identity provider.
    type: str
  id:
    description:
      - The ID (and name) of the identity provider.
    type: str
    required: true
    aliases: ['name']
  is_enabled:
    description:
      - Whether the identity provider is enabled or not.
      - Will default to C(false) when creating a new identity provider.
    type: bool
    aliases: ['enabled']
  remote_ids:
    description:
      - "List of the unique identity provider's remote IDs."
      - Will default to an empty list when creating a new identity provider.
    type: list
    elements: str
  state:
    description:
      - Whether the identity provider should be C(present) or C(absent).
    choices: ['present', 'absent']
    default: present
    type: str
extends_documentation_fragment:
  - openstack.cloud.openstack
'''

EXAMPLES = r'''
- name: Create an identity provider
  openstack.cloud.federation_idp:
    cloud: example_cloud
    name: example_provider
    domain_id: 0123456789abcdef0123456789abcdef
    description: 'My example IDP'
    remote_ids:
      - 'https://auth.example.com/auth/realms/ExampleRealm'

- name: Delete an identity provider
  openstack.cloud.federation_idp:
    cloud: example_cloud
    name: example_provider
    state: absent
'''

RETURN = r'''
identity_provider:
  description: Dictionary describing the identity providers
  returned: On success when I(state) is C(present).
  type: dict
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
from ansible_collections.openstack.cloud.plugins.module_utils.resource import StateMachine


class IdentityProviderModule(OpenStackModule):
    argument_spec = dict(
        description=dict(),
        domain_id=dict(),
        id=dict(required=True, aliases=['name']),
        is_enabled=dict(type='bool', aliases=['enabled']),
        remote_ids=dict(type='list', elements='str'),
        state=dict(default='present', choices=['absent', 'present']),
    )
    module_kwargs = dict(
        supports_check_mode=True,
    )

    def run(self):
        sm = StateMachine(connection=self.conn,
                          service_name='identity',
                          type_name='identity_provider',
                          sdk=self.sdk)

        kwargs = dict((k, self.params[k])
                      for k in ['state', 'timeout']
                      if self.params[k] is not None)

        kwargs['attributes'] = \
            dict((k, self.params[k])
                 for k in ['description', 'domain_id', 'id', 'is_enabled',
                           'remote_ids']
                 if self.params[k] is not None)

        identity_provider, is_changed = \
            sm(check_mode=self.ansible.check_mode,
               updateable_attributes=None,
               non_updateable_attributes=['domain_id'],
               wait=False,
               **kwargs)

        if identity_provider is None:
            self.exit_json(changed=is_changed)
        else:
            self.exit_json(
                changed=is_changed,
                identity_provider=identity_provider.to_dict(computed=False))


def main():
    module = IdentityProviderModule()
    module()


if __name__ == '__main__':
    main()
