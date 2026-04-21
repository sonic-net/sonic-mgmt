#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2020 by Tino Schreiber (Open Telekom Cloud), operated by T-Systems International GmbH
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: security_group_rule_info
short_description: Fetch OpenStack network (Neutron) security group rules
author: OpenStack Ansible SIG
description:
  - Fetch security group rules from OpenStack network (Neutron) API.
options:
  description:
    description:
      - Filter the list result by the human-readable description of
        the resource.
    type: str
  direction:
    description:
      - Filter the security group rule list result by the direction in
        which the security group rule is applied.
    choices: ['egress', 'ingress']
    type: str
  ether_type:
    description:
      - Filter the security group rule list result by the ether_type of
        network traffic. The value must be IPv4 or IPv6.
    choices: ['IPv4', 'IPv6']
    type: str
    aliases: ['ethertype']
  id:
    description:
      - Filter the list result by the ID of the security group rule.
    type: str
    aliases: ['rule']
  port_range_min:
    description:
      - Starting port
    type: int
  port_range_max:
    description:
      - Ending port
    type: int
  project:
    description:
      - Unique name or ID of the project.
    required: false
    type: str
  protocol:
    description:
      - Filter the security group rule list result by the IP protocol.
    type: str
  remote_group:
    description:
      - Filter the security group rule list result by the name or ID of the
        remote group that associates with this security group rule.
    type: str
  remote_ip_prefix:
    description:
      - Source IP address(es) in CIDR notation (exclusive with remote_group)
    type: str
  revision_number:
    description:
      - Filter the list result by the revision number of the resource.
    type: int
  security_group:
    description:
      - Name or ID of the security group
    type: str
extends_documentation_fragment:
  - openstack.cloud.openstack
'''

EXAMPLES = r'''
- name: Fetch all security group rules
  openstack.cloud.security_group_rule_info:
    cloud: devstack

- name: Filter security group rules for port 80 and name
  openstack.cloud.security_group_rule_info:
    cloud: devstack
    security_group: foo
    protocol: tcp
    port_range_min: 80
    port_range_max: 80
    remote_ip_prefix: 0.0.0.0/0

- name: Filter for ICMP rules
  openstack.cloud.security_group_rule_info:
    cloud: devstack
    protocol: icmp
'''

RETURN = r'''
security_group_rules:
  description: List of dictionaries describing security group rules.
  type: list
  elements: dict
  returned: always
  contains:
    created_at:
      description: Timestamp when the security group rule was created.
      type: str
    description:
      description: Human-readable description of the resource.
      type: str
      sample: 'My description.'
    direction:
      description: The direction in which the security group rule is applied.
      type: str
      sample: 'egress'
    ether_type:
      description: One of IPv4 or IPv6.
      type: str
      sample: 'IPv4'
    id:
      description: Unique rule UUID.
      type: str
    name:
      description: Name of the resource.
      type: str
    port_range_max:
      description: The maximum port number in the range that is matched by
                  the security group rule.
      type: int
      sample: 8000
    port_range_min:
      description: The minimum port number in the range that is matched by
                   the security group rule.
      type: int
      sample: 8000
    project_id:
      description: The ID of the project.
      type: str
      sample: 'e4f50856753b4dc6afee5fa6b9b6c550'
    protocol:
      description: The protocol that is matched by the security group rule.
      type: str
      sample: 'tcp'
    remote_address_group_id:
      description: The remote address group ID to be associated with this
                   security group rule.
      type: str
    remote_group_id:
      description: The remote security group ID to be associated with this
                   security group rule.
      type: str
    remote_ip_prefix:
      description: The remote IP prefix to be associated with this security
                   group rule.
      type: str
    revision_number:
      description: The remote IP prefix to be associated with this security
                   group rule.
      type: str
      sample: '0.0.0.0/0'
    security_group_id:
      description: The security group ID to associate with this security
                   group rule.
      type: str
      sample: '729b9660-a20a-41fe-bae6-ed8fa7f69123'
    tags:
      description: The security group ID to associate with this security
                   group rule.
      type: str
      sample: '729b9660-a20a-41fe-bae6-ed8fa7f69123'
    tenant_id:
      description: The ID of the project. Deprecated.
      type: str
      sample: 'e4f50856753b4dc6afee5fa6b9b6c550'
    updated_at:
      description: Time at which the resource has been updated
                   (in UTC ISO8601 format).
      type: str
      sample: '2018-03-19T19:16:56Z'
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import (
    OpenStackModule)


class SecurityGroupRuleInfoModule(OpenStackModule):
    argument_spec = dict(
        description=dict(),
        direction=dict(choices=['egress', 'ingress']),
        ether_type=dict(choices=['IPv4', 'IPv6'], aliases=['ethertype']),
        id=dict(aliases=['rule']),
        port_range_min=dict(type='int'),
        port_range_max=dict(type='int'),
        project=dict(),
        protocol=dict(),
        remote_group=dict(),
        remote_ip_prefix=dict(),
        revision_number=dict(type='int'),
        security_group=dict()
    )

    module_kwargs = dict(
        mutually_exclusive=[
            ('remote_ip_prefix', 'remote_group'),
        ],
        supports_check_mode=True
    )

    def run(self):
        filters = dict((k, self.params[k])
                       for k in ['description', 'direction', 'ether_type',
                                 'id', 'port_range_min', 'port_range_max',
                                 'protocol', 'remote_group',
                                 'revision_number', 'remote_ip_prefix']
                       if self.params[k] is not None)

        project_name_or_id = self.params['project']
        if project_name_or_id is not None:
            project = self.conn.find_project(project_name_or_id)
            if not project:
                self.exit_json(changed=False, security_group_rules=[])
            filters['project_id'] = project.id

        security_group_name_or_id = self.params['security_group']
        if security_group_name_or_id is not None:
            security_group = self.conn.network.\
                find_security_group(security_group_name_or_id)
            if not security_group:
                self.exit_json(changed=False, security_group_rules=[])
            filters['security_group_id'] = security_group.id

        security_group_rules = \
            self.conn.network.security_group_rules(**filters)

        self.exit_json(changed=False,
                       security_group_rules=[r.to_dict(computed=False)
                                             for r in security_group_rules])


def main():
    module = SecurityGroupRuleInfoModule()
    module()


if __name__ == '__main__':
    main()
