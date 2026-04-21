#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2015 Hewlett-Packard Development Company, L.P.
# Copyright (c) 2013, Benno Joy <benno@ansible.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: security_group_rule
short_description: Manage security group rules in OpenStack network (Neutron)
author: OpenStack Ansible SIG
description:
  - Add or remove security group rule to/from OpenStack network (Neutron)
    service.
  - Use I(security_group_rules) in M(openstack.cloud.security_group) to define
    a set of security group rules. It will be much faster than using this
    module when creating or removing several security group rules because the
    latter will do individual calls to OpenStack network (Neutron) API for each
    security group rule.
options:
  description:
    description:
      - Description of the security group rule.
    type: str
  direction:
    description:
      - The direction in which the security group rule is applied.
      - Not all providers support C(egress).
    choices: ['egress', 'ingress']
    default: ingress
    type: str
  ether_type:
    description:
      - Must be IPv4 or IPv6, and addresses represented in CIDR must
        match the ingress or egress rules. Not all providers support IPv6.
    choices: ['IPv4', 'IPv6']
    default: IPv4
    type: str
    aliases: ['ethertype']
  port_range_max:
    description:
      - The maximum port number in the range that is matched by the security
        group rule.
      - If the protocol is TCP, UDP, DCCP, SCTP or UDP-Lite this value must be
        greater than or equal to the I(port_range_min) attribute value.
      - If the protocol is ICMP, this value must be an ICMP code.
    type: int
  port_range_min:
    description:
      - The minimum port number in the range that is matched by the security
        group rule.
      - If the protocol is TCP, UDP, DCCP, SCTP or UDP-Lite this value must be
        less than or equal to the port_range_max attribute value.
      - If the protocol is ICMP, this value must be an ICMP type.
    type: int
  project:
    description:
      - Unique name or ID of the project.
    type: str
  protocol:
    description:
      - The IP protocol can be represented by a string, an integer, or null.
      - Valid string or integer values are C(any) or C(0), C(ah) or C(51),
        C(dccp) or C(33), C(egp) or C(8), C(esp) or C(50), C(gre) or C(47),
        C(icmp) or C(1), C(icmpv6) or C(58), C(igmp) or C(2), C(ipip) or C(4),
        C(ipv6-encap) or C(41), C(ipv6-frag) or C(44), C(ipv6-icmp) or C(58),
        C(ipv6-nonxt) or C(59), C(ipv6-opts) or C(60), C(ipv6-route) or C(43),
        C(ospf) or C(89), C(pgm) or C(113), C(rsvp) or C(46), C(sctp) or
        C(132), C(tcp) or C(6), C(udp) or C(17), C(udplite) or C(136), C(vrrp)
        or C(112).
      - Additionally, any integer value between C([0-255]) is also valid.
      - The string any (or integer 0) means all IP protocols.
      - See the constants in neutron_lib.constants for the most up-to-date
        list of supported strings.
    type: str
  remote_group:
    description:
      - Name or ID of the security group to link.
      - Mutually exclusive with I(remote_ip_prefix).
    type: str
  remote_ip_prefix:
    description:
      - Source IP address(es) in CIDR notation.
      - When a netmask such as C(/32) is missing from I(remote_ip_prefix), then
        this module will fail on updates with OpenStack error message
        C(Security group rule already exists.).
      - Mutually exclusive with I(remote_group).
    type: str
  security_group:
    description:
      - Name or ID of the security group.
    required: true
    type: str
  state:
    description:
      - Should the resource be present or absent.
    choices: [present, absent]
    default: present
    type: str
extends_documentation_fragment:
  - openstack.cloud.openstack
'''

EXAMPLES = r'''
- name: Create a security group rule
  openstack.cloud.security_group_rule:
    cloud: mordred
    security_group: foo
    protocol: tcp
    port_range_min: 80
    port_range_max: 80
    remote_ip_prefix: 0.0.0.0/0

- name: Create a security group rule for ping
  openstack.cloud.security_group_rule:
    cloud: mordred
    security_group: foo
    protocol: icmp
    remote_ip_prefix: 0.0.0.0/0

- name: Another way to create the ping rule
  openstack.cloud.security_group_rule:
    cloud: mordred
    security_group: foo
    protocol: icmp
    port_range_min: -1
    port_range_max: -1
    remote_ip_prefix: 0.0.0.0/0

- name: Create a TCP rule covering all ports
  openstack.cloud.security_group_rule:
    cloud: mordred
    security_group: foo
    protocol: tcp
    port_range_min: 1
    port_range_max: 65535
    remote_ip_prefix: 0.0.0.0/0

- name: Another way to create the TCP rule above (defaults to all ports)
  openstack.cloud.security_group_rule:
    cloud: mordred
    security_group: foo
    protocol: tcp
    remote_ip_prefix: 0.0.0.0/0

- name: Create a rule for VRRP with numbered protocol 112
  openstack.cloud.security_group_rule:
    security_group: loadbalancer_sg
    protocol: 112
    remote_group: loadbalancer-node_sg

- name: Create a security group rule for a given project
  openstack.cloud.security_group_rule:
    cloud: mordred
    security_group: foo
    protocol: icmp
    remote_ip_prefix: 0.0.0.0/0
    project: myproj

- name: Remove the default created egress rule for IPv4
  openstack.cloud.security_group_rule:
    cloud: mordred
    security_group: foo
    protocol: any
    remote_ip_prefix: 0.0.0.0/0
'''

RETURN = r'''
rule:
  description: Dictionary describing the security group rule
  type: dict
  returned: On success when I(state) is C(present).
  contains:
    created_at:
      description: Timestamp when the resource was created
      type: str
    description:
      description: Description of the resource
      type: str
    direction:
      description: The direction in which the security group rule is applied.
      type: str
      sample: 'egress'
    ether_type:
      description: Either IPv4 or IPv6
      type: str
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
      description: ID of the project the resource belongs to.
      type: str
    protocol:
      description: The protocol that is matched by the security group rule.
      type: str
      sample: 'tcp'
    remote_address_group_id:
      description: The remote address group ID to be associated with this
                   security group rule.
      type: str
      sample: '0.0.0.0/0'
    remote_group_id:
      description: The remote security group ID to be associated with this
                   security group rule.
      type: str
      sample: '0.0.0.0/0'
    remote_ip_prefix:
      description: The remote IP prefix to be associated with this security
                   group rule.
      type: str
      sample: '0.0.0.0/0'
    revision_number:
      description: Revision number
      type: int
      sample: 0
    security_group_id:
      description: The security group ID to associate with this security group
                   rule.
      type: str
    tags:
      description: Tags associated with resource.
      type: list
      elements: str
    tenant_id:
      description: ID of the project the resource belongs to. Deprecated.
      type: str
    updated_at:
      description: Timestamp when the security group rule was last updated.
      type: str
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import (
    OpenStackModule)


class SecurityGroupRuleModule(OpenStackModule):
    # NOTE: Keep handling of security group rules synchronized with
    #       security_group.py!

    argument_spec = dict(
        description=dict(),
        direction=dict(default='ingress', choices=['egress', 'ingress']),
        ether_type=dict(default='IPv4', choices=['IPv4', 'IPv6'],
                        aliases=['ethertype']),
        port_range_max=dict(type='int'),
        port_range_min=dict(type='int'),
        project=dict(),
        protocol=dict(),
        remote_group=dict(),
        remote_ip_prefix=dict(),
        security_group=dict(required=True),
        state=dict(default='present', choices=['absent', 'present']),
    )

    module_kwargs = dict(
        mutually_exclusive=[
            ['remote_ip_prefix', 'remote_group'],
        ],
        supports_check_mode=True,
    )

    def run(self):
        state = self.params['state']

        security_group_rule = self._find()

        if self.ansible.check_mode:
            self.exit_json(
                changed=self._will_change(state, security_group_rule))

        if state == 'present' and not security_group_rule:
            # Create security_group_rule
            security_group_rule = self._create()
            self.exit_json(changed=True,
                           rule=security_group_rule.to_dict(computed=False))

        elif state == 'present' and security_group_rule:
            # Only exact matches will cause security_group_rule to be not None
            self.exit_json(changed=False,
                           rule=security_group_rule.to_dict(computed=False))
        elif state == 'absent' and security_group_rule:
            # Delete security_group_rule
            self._delete(security_group_rule)
            self.exit_json(changed=True)

        elif state == 'absent' and not security_group_rule:
            # Do nothing
            self.exit_json(changed=False)

    def _create(self):
        prototype = self._define_prototype()
        return self.conn.network.create_security_group_rule(**prototype)

    def _define_prototype(self):
        filters = {}
        prototype = dict((k, self.params[k])
                         for k in ['description', 'direction',
                                   'remote_ip_prefix']
                         if self.params[k] is not None)

        # When remote_ip_prefix is missing a netmask, then Neutron will add
        # a netmask using Python library netaddr [0] and its IPNetwork
        # class [1]. We do not want to introduce additional Python
        # dependencies to our code base and neither want to replicate
        # netaddr's parse_ip_network code here. So we do not handle
        # remote_ip_prefix without a netmask and instead let Neutron handle
        # it.
        # [0] https://opendev.org/openstack/neutron/src/commit/\
        #     43d94640568828f5e98bbb1e9df985ec3f1bb2d2/neutron/db/securitygroups_db.py#L775
        # [1] https://github.com/netaddr/netaddr/blob/\
        #     b1d8f016abee00c8a93e35b928acdc22797c800a/netaddr/ip/__init__.py#L841
        # [2] https://github.com/netaddr/netaddr/blob/\
        #     b1d8f016abee00c8a93e35b928acdc22797c800a/netaddr/ip/__init__.py#L773

        project_name_or_id = self.params['project']
        if project_name_or_id is not None:
            project = self.conn.identity.find_project(project_name_or_id,
                                                      ignore_missing=False)
            filters = {'project_id': project.id}
            prototype['project_id'] = project.id

        security_group_name_or_id = self.params['security_group']
        security_group = self.conn.network.find_security_group(
            security_group_name_or_id, ignore_missing=False, **filters)
        prototype['security_group_id'] = security_group.id

        remote_group = None
        remote_group_name_or_id = self.params['remote_group']
        if remote_group_name_or_id is not None:
            remote_group = self.conn.network.find_security_group(
                remote_group_name_or_id, ignore_missing=False)
            prototype['remote_group_id'] = remote_group.id

        ether_type = self.params['ether_type']
        if ether_type is not None:
            prototype['ether_type'] = ether_type

        protocol = self.params['protocol']
        if protocol is not None and protocol not in ['any', '0']:
            prototype['protocol'] = protocol

        port_range_max = self.params['port_range_max']
        port_range_min = self.params['port_range_min']

        if protocol in ['icmp', 'ipv6-icmp']:
            # Check if the user is supplying -1 for ICMP.
            if port_range_max is not None and int(port_range_max) != -1:
                prototype['port_range_max'] = int(port_range_max)
            if port_range_min is not None and int(port_range_min) != -1:
                prototype['port_range_min'] = int(port_range_min)
        elif protocol in ['tcp', 'udp']:
            if port_range_max is not None and int(port_range_max) != -1:
                prototype['port_range_max'] = int(port_range_max)
            if port_range_min is not None and int(port_range_min) != -1:
                prototype['port_range_min'] = int(port_range_min)
        elif protocol in ['any', '0']:
            # Rules with 'any' protocol do not match ports
            pass
        else:
            if port_range_max is not None:
                prototype['port_range_max'] = int(port_range_max)
            if port_range_min is not None:
                prototype['port_range_min'] = int(port_range_min)

        return prototype

    def _delete(self, security_group_rule):
        self.conn.network.delete_security_group_rule(security_group_rule.id)

    def _find(self):
        # Replacing this code with self.conn.network.find_security_group_rule()
        # is not possible because the latter requires an id or name.
        matches = self._find_matches()
        if len(matches) > 1:
            self.fail_json(msg='Found more a single matching security group'
                               ' rule which match the given parameters.')
        elif len(matches) == 1:
            return self.conn.network.get_security_group_rule(matches[0]['id'])
        else:  # len(matches) == 0
            return None

    def _find_matches(self):
        prototype = self._define_prototype()

        security_group = self.conn.network.\
            get_security_group(prototype['security_group_id'])

        if 'ether_type' in prototype:
            prototype['ethertype'] = prototype.pop('ether_type')

        if 'protocol' in prototype and prototype['protocol'] in ['tcp', 'udp']:
            # Check if the user is supplying -1, 1 to 65535 or None values
            # for full TPC or UDP port range.
            # (None, None) == (1, 65535) == (-1, -1)
            if 'port_range_max' in prototype \
               and prototype['port_range_max'] in [-1, 65535]:
                prototype.pop('port_range_max')
            if 'port_range_min' in prototype \
               and prototype['port_range_min'] in [-1, 1]:
                prototype.pop('port_range_min')

        return [r for r in security_group.security_group_rules
                if all(r[k] == prototype[k] for k in prototype.keys())]

    def _will_change(self, state, security_group_rule):
        if state == 'present' and not security_group_rule:
            return True
        elif state == 'present' and security_group_rule:
            # Only exact matches will cause security_group_rule to be not None
            return False
        elif state == 'absent' and security_group_rule:
            return True
        else:
            # state == 'absent' and not security_group_rule:
            return False


def main():
    module = SecurityGroupRuleModule()
    module()


if __name__ == '__main__':
    main()
