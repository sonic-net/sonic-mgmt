#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021 by Open Telekom Cloud, operated by T-Systems International GmbH
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = '''
---
module: floating_ip_info
short_description: Get information about floating ips
author: OpenStack Ansible SIG
description:
  - Get a generator of floating ips.
options:
  description:
    description:
      - The description of a floating IP.
    type: str
  fixed_ip_address:
    description:
      - The fixed IP address associated with a floating IP address.
    type: str
  floating_ip_address:
    description:
      -  The IP address of a floating IP.
    type: str
  floating_network:
    description:
      - The name or id of the network associated with a floating IP.
    type: str
  port:
    description:
      - The name or id of the port to which a floating IP is associated.
    type: str
  project:
    description:
      - The name or ID of the project a floating IP is associated with.
    type: str
    aliases: ['project_id']
  router:
    description:
      - The name or id of an associated router.
    type: str
  status:
    description:
      - The status of a floating IP.
    choices: ['active', 'down']
    type: str
extends_documentation_fragment:
- openstack.cloud.openstack
'''

RETURN = '''
floating_ips:
  description: The floating ip objects list.
  type: list
  elements: dict
  returned: success
  contains:
    created_at:
      description: Timestamp at which the floating IP was assigned.
      type: str
    description:
      description: The description of a floating IP.
      type: str
    dns_domain:
      description: The DNS domain.
      type: str
    dns_name:
      description: The DNS name.
      type: str
    fixed_ip_address:
      description: The fixed IP address associated with a floating IP address.
      type: str
    floating_ip_address:
      description: The IP address of a floating IP.
      type: str
    floating_network_id:
      description: The id of the network associated with a floating IP.
      type: str
    id:
      description: Id of the floating ip.
      type: str
    name:
      description: Name of the floating ip.
      type: str
    port_details:
      description: |
        The details of the port that this floating IP associates
        with. Present if C(fip-port-details) extension is loaded.
      type: dict
    port_id:
      description: The port ID floating ip associated with.
      type: str
    project_id:
      description: The ID of the project this floating IP is associated with.
      type: str
    qos_policy_id:
      description: The ID of the QoS policy attached to the floating IP.
      type: str
    revision_number:
      description: Revision number.
      type: str
    router_id:
      description: The id of the router floating ip associated with.
      type: str
    status:
      description: |
        The status of a floating IP, which can be 'ACTIVE' or 'DOWN'.
      type: str
    subnet_id:
      description: The id of the subnet the floating ip associated with.
      type: str
    tags:
      description: List of tags.
      type: list
      elements: str
    updated_at:
      description: Timestamp at which the floating IP was last updated.
      type: str
'''

EXAMPLES = '''
# Getting all floating ips
- openstack.cloud.floating_ip_info:
  register: fips

# Getting fip by associated fixed IP address.
- openstack.cloud.floating_ip_info:
    fixed_ip_address: 192.168.10.8
  register: fip

# Getting fip by associated router.
- openstack.cloud.floating_ip_info:
    router: my-router
  register: fip
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import OpenStackModule


class FloatingIPInfoModule(OpenStackModule):
    argument_spec = dict(
        description=dict(),
        fixed_ip_address=dict(),
        floating_ip_address=dict(),
        floating_network=dict(),
        port=dict(),
        project=dict(aliases=['project_id']),
        router=dict(),
        status=dict(choices=['active', 'down']),
    )
    module_kwargs = dict(
        supports_check_mode=True
    )

    def run(self):
        query = dict((k, self.params[k])
                     for k in ['description', 'fixed_ip_address',
                               'floating_ip_address']
                     if self.params[k] is not None)

        for k in ['port', 'router']:
            if self.params[k]:
                k_id = '{0}_id'.format(k)
                find_name = 'find_{0}'.format(k)
                query[k_id] = getattr(self.conn.network, find_name)(
                    name_or_id=self.params[k], ignore_missing=False)['id']

        floating_network_name_or_id = self.params['floating_network']
        if floating_network_name_or_id:
            query['floating_network_id'] = self.conn.network.find_network(
                name_or_id=floating_network_name_or_id,
                ignore_missing=False)['id']

        project_name_or_id = self.params['project']
        if project_name_or_id:
            project = self.conn.identity.find_project(project_name_or_id)
            if project:
                query['project_id'] = project['id']
            else:
                # caller might not have permission to query projects
                # so assume she gave a project id
                query['project_id'] = project_name_or_id

        status = self.params['status']
        if status:
            query['status'] = status.upper()

        self.exit_json(
            changed=False,
            floating_ips=[ip.to_dict(computed=False)
                          for ip in self.conn.network.ips(**query)])


def main():
    module = FloatingIPInfoModule()
    module()


if __name__ == '__main__':
    main()
