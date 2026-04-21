#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: keystone_federation_protocol_info
short_description: Fetch Keystone federation protocols
author: OpenStack Ansible SIG
description:
  - Fetch Keystone federation protocols.
options:
  name:
    description:
      - ID or name of the federation protocol.
    type: str
    aliases: ['id']
  idp:
    description:
      - ID or name of the identity provider this protocol is associated with.
    aliases: ['idp_id', 'idp_name']
    required: true
    type: str
notes:
    - Name equals the ID of a federation protocol.
    - Name equals the ID of an identity provider.
extends_documentation_fragment:
  - openstack.cloud.openstack
'''

EXAMPLES = r'''
- name: Fetch all federation protocols attached to an identity provider
  openstack.cloud.keystone_federation_protocol_info:
    cloud: example_cloud
    idp: example_idp

- name: Fetch federation protocol by name
  openstack.cloud.keystone_federation_protocol_info:
    cloud: example_cloud
    idp: example_idp
    name: example_protocol
'''

RETURN = r'''
protocols:
    description: List of federation protocol dictionaries.
    returned: always
    type: list
    elements: dict
    contains:
        id:
            description: ID of the federation protocol.
            returned: success
            type: str
        mapping_id:
            description: The definition of the federation protocol.
            returned: success
            type: str
        name:
            description: Name of the protocol. Equal to C(id).
            returned: success
            type: str
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import OpenStackModule


class IdentityFederationProtocolInfoModule(OpenStackModule):
    argument_spec = dict(
        name=dict(aliases=['id']),
        idp=dict(required=True, aliases=['idp_id', 'idp_name']),
    )

    module_kwargs = dict(
        supports_check_mode=True
    )

    def run(self):
        # name is id for federation protocols
        id = self.params['name']

        # name is id for identity providers
        idp_id = self.params['idp']

        if id:
            protocol = self.conn.identity.find_federation_protocol(idp_id, id)
            protocols = [protocol] if protocol else []
        else:
            protocols = self.conn.identity.federation_protocols(idp_id)

        self.exit_json(changed=False,
                       protocols=[p.to_dict(computed=False)
                                  for p in protocols])


def main():
    module = IdentityFederationProtocolInfoModule()
    module()


if __name__ == '__main__':
    main()
