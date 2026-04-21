#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2015 Hewlett-Packard Development Company, L.P.
# Copyright (c) 2013, Benno Joy <benno@ansible.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: security_group
short_description: Manage Neutron security groups of an OpenStack cloud.
author: OpenStack Ansible SIG
description:
  - Add or remove Neutron security groups to/from an OpenStack cloud.
options:
  description:
    description:
      - Long description of the purpose of the security group.
    type: str
  name:
    description:
      - Name that has to be given to the security group. This module
        requires that security group names be unique.
    required: true
    type: str
  project:
    description:
      - Unique name or ID of the project.
    type: str
  security_group_rules:
    description:
      - List of security group rules.
      - When I(security_group_rules) is not defined, Neutron might create this
        security group with a default set of rules.
      - Security group rules which are listed in I(security_group_rules)
        but not defined in this security group will be created.
      - When I(security_group_rules) is not set, existing security group rules
        which are not listed in I(security_group_rules) will be deleted.
      - When updating a security group, one has to explicitly list rules from
        Neutron's defaults in I(security_group_rules) if those rules should be
        kept. Rules which are not listed in I(security_group_rules) will be
        deleted.
    type: list
    elements: dict
    suboptions:
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
      port_range_max:
        description:
          - The maximum port number in the range that is matched by the
            security group rule.
          - If the protocol is TCP, UDP, DCCP, SCTP or UDP-Lite this value must
            be greater than or equal to the I(port_range_min) attribute value.
          - If the protocol is ICMP, this value must be an ICMP code.
        type: int
      port_range_min:
        description:
          - The minimum port number in the range that is matched by the
            security group rule.
          - If the protocol is TCP, UDP, DCCP, SCTP or UDP-Lite this value must
            be less than or equal to the port_range_max attribute value.
          - If the protocol is ICMP, this value must be an ICMP type.
        type: int
      protocol:
        description:
          - The IP protocol can be represented by a string, an integer, or
            null.
          - Valid string or integer values are C(any) or C(0), C(ah) or C(51),
            C(dccp) or C(33), C(egp) or C(8), C(esp) or C(50), C(gre) or C(47),
            C(icmp) or C(1), C(icmpv6) or C(58), C(igmp) or C(2), C(ipip) or
            C(4), C(ipv6-encap) or C(41), C(ipv6-frag) or C(44), C(ipv6-icmp)
            or C(58), C(ipv6-nonxt) or C(59), C(ipv6-opts) or C(60),
            C(ipv6-route) or C(43), C(ospf) or C(89), C(pgm) or C(113), C(rsvp)
            or C(46), C(sctp) or C(132), C(tcp) or C(6), C(udp) or C(17),
            C(udplite) or C(136), C(vrrp) or C(112).
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
          - When a netmask such as C(/32) is missing from I(remote_ip_prefix),
            then this module will fail on updates with OpenStack error message
            C(Security group rule already exists.).
          - Mutually exclusive with I(remote_group).
        type: str
  state:
    description:
      - Should the resource be present or absent.
    choices: [present, absent]
    default: present
    type: str
  stateful:
    description:
      - Should the resource be stateful or stateless.
    type: bool
extends_documentation_fragment:
  - openstack.cloud.openstack
'''

RETURN = r'''
security_group:
  description: Dictionary describing the security group.
  type: dict
  returned: On success when I(state) is C(present).
  contains:
    created_at:
      description: Creation time of the security group
      type: str
      sample: "yyyy-mm-dd hh:mm:ss"
    description:
      description: Description of the security group
      type: str
      sample: "My security group"
    id:
      description: ID of the security group
      type: str
      sample: "d90e55ba-23bd-4d97-b722-8cb6fb485d69"
    name:
      description: Name of the security group.
      type: str
      sample: "my-sg"
    project_id:
      description: Project ID where the security group is located in.
      type: str
      sample: "25d24fc8-d019-4a34-9fff-0a09fde6a567"
    revision_number:
      description: The revision number of the resource.
      type: int
    tenant_id:
      description: Tenant ID where the security group is located in. Deprecated
      type: str
      sample: "25d24fc8-d019-4a34-9fff-0a09fde6a567"
    security_group_rules:
      description: Specifies the security group rule list
      type: list
      sample: [
        {
          "id": "d90e55ba-23bd-4d97-b722-8cb6fb485d69",
          "direction": "ingress",
          "protocol": null,
          "ethertype": "IPv4",
          "description": null,
          "remote_group_id": "0431c9c5-1660-42e0-8a00-134bec7f03e2",
          "remote_ip_prefix": null,
          "tenant_id": "bbfe8c41dd034a07bebd592bf03b4b0c",
          "port_range_max": null,
          "port_range_min": null,
          "security_group_id": "0431c9c5-1660-42e0-8a00-134bec7f03e2"
        },
        {
          "id": "aecff4d4-9ce9-489c-86a3-803aedec65f7",
          "direction": "egress",
          "protocol": null,
          "ethertype": "IPv4",
          "description": null,
          "remote_group_id": null,
          "remote_ip_prefix": null,
          "tenant_id": "bbfe8c41dd034a07bebd592bf03b4b0c",
          "port_range_max": null,
          "port_range_min": null,
          "security_group_id": "0431c9c5-1660-42e0-8a00-134bec7f03e2"
        }
      ]
    stateful:
      description: Indicates if the security group is stateful or stateless.
      type: bool
    tags:
      description: The list of tags on the resource.
      type: list
    updated_at:
      description: Update time of the security group
      type: str
      sample: "yyyy-mm-dd hh:mm:ss"
'''

EXAMPLES = r'''
- name: Create a security group
  openstack.cloud.security_group:
    cloud: mordred
    state: present
    name: foo
    description: security group for foo servers

- name: Create a stateless security group
  openstack.cloud.security_group:
    cloud: mordred
    state: present
    stateful: false
    name: foo
    description: stateless security group for foo servers

- name: Update the existing 'foo' security group description
  openstack.cloud.security_group:
    cloud: mordred
    state: present
    name: foo
    description: updated description for the foo security group

- name: Create a security group for a given project
  openstack.cloud.security_group:
    cloud: mordred
    state: present
    name: foo
    project: myproj

- name: Create (or update) a security group with security group rules
  openstack.cloud.security_group:
    cloud: mordred
    state: present
    name: foo
    security_group_rules:
      - ether_type: IPv6
        direction: egress
      - ether_type: IPv4
        direction: egress

- name: Create (or update) security group without security group rules
  openstack.cloud.security_group:
    cloud: mordred
    state: present
    name: foo
    security_group_rules: []
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import OpenStackModule


class SecurityGroupModule(OpenStackModule):
    # NOTE: Keep handling of security group rules synchronized with
    #       security_group_rule.py!

    argument_spec = dict(
        description=dict(),
        name=dict(required=True),
        project=dict(),
        security_group_rules=dict(
            type="list", elements="dict",
            options=dict(
                description=dict(),
                direction=dict(default="ingress",
                               choices=["egress", "ingress"]),
                ether_type=dict(default="IPv4", choices=["IPv4", "IPv6"]),
                port_range_max=dict(type="int"),
                port_range_min=dict(type="int"),
                protocol=dict(),
                remote_group=dict(),
                remote_ip_prefix=dict(),
            ),
        ),
        state=dict(default='present', choices=['absent', 'present']),
        stateful=dict(type="bool"),
    )

    module_kwargs = dict(
        supports_check_mode=True,
    )

    def run(self):
        state = self.params['state']

        security_group = self._find()

        if self.ansible.check_mode:
            self.exit_json(changed=self._will_change(state, security_group))

        if state == 'present' and not security_group:
            # Create security_group
            security_group = self._create()
            self.exit_json(
                changed=True,
                security_group=security_group.to_dict(computed=False))

        elif state == 'present' and security_group:
            # Update security_group
            update = self._build_update(security_group)
            if update:
                security_group = self._update(security_group, update)

            self.exit_json(
                changed=bool(update),
                security_group=security_group.to_dict(computed=False))

        elif state == 'absent' and security_group:
            # Delete security_group
            self._delete(security_group)
            self.exit_json(changed=True)

        elif state == 'absent' and not security_group:
            # Do nothing
            self.exit_json(changed=False)

    def _build_update(self, security_group):
        return {
            **self._build_update_security_group(security_group),
            **self._build_update_security_group_rules(security_group)}

    def _build_update_security_group(self, security_group):
        update = {}

        # module options name and project are used to find security group
        # and thus cannot be updated

        non_updateable_keys = [k for k in []
                               if self.params[k] is not None
                               and self.params[k] != security_group[k]]

        if non_updateable_keys:
            self.fail_json(msg='Cannot update parameters {0}'
                               .format(non_updateable_keys))

        attributes = dict((k, self.params[k])
                          for k in ['description']
                          if self.params[k] is not None
                          and self.params[k] != security_group[k])

        if attributes:
            update['attributes'] = attributes

        return update

    def _build_update_security_group_rules(self, security_group):

        if self.params['security_group_rules'] is None:
            # Consider a change of security group rules only when option
            # 'security_group_rules' was defined explicitly, because undefined
            # options in our Ansible modules denote "apply no change"
            return {}

        def find_security_group_rule_match(prototype, security_group_rules):
            matches = [r for r in security_group_rules
                       if is_security_group_rule_match(prototype, r)]
            if len(matches) > 1:
                self.fail_json(msg='Found more a single matching security'
                                   ' group rule which match the given'
                                   ' parameters.')
            elif len(matches) == 1:
                return matches[0]
            else:  # len(matches) == 0
                return None

        def is_security_group_rule_match(prototype, security_group_rule):
            skip_keys = ['ether_type']
            if 'ether_type' in prototype \
               and security_group_rule['ethertype'] != prototype['ether_type']:
                return False

            if 'protocol' in prototype \
               and prototype['protocol'] in ['tcp', 'udp']:
                # Check if the user is supplying -1, 1 to 65535 or None values
                # for full TPC or UDP port range.
                # (None, None) == (1, 65535) == (-1, -1)
                if 'port_range_max' in prototype \
                   and prototype['port_range_max'] in [-1, 65535]:
                    if security_group_rule['port_range_max'] is not None:
                        return False
                    skip_keys.append('port_range_max')
                if 'port_range_min' in prototype \
                   and prototype['port_range_min'] in [-1, 1]:
                    if security_group_rule['port_range_min'] is not None:
                        return False
                    skip_keys.append('port_range_min')

            if all(security_group_rule[k] == prototype[k]
                   for k in (set(prototype.keys()) - set(skip_keys))):
                return security_group_rule
            else:
                return None

        update = {}
        keep_security_group_rules = {}
        create_security_group_rules = []
        delete_security_group_rules = []

        for prototype in self._generate_security_group_rules(security_group):
            match = find_security_group_rule_match(
                prototype, security_group.security_group_rules)
            if match:
                keep_security_group_rules[match['id']] = match
            else:
                create_security_group_rules.append(prototype)

        for security_group_rule in security_group.security_group_rules:
            if (security_group_rule['id']
               not in keep_security_group_rules.keys()):
                delete_security_group_rules.append(security_group_rule)

        if create_security_group_rules:
            update['create_security_group_rules'] = create_security_group_rules

        if delete_security_group_rules:
            update['delete_security_group_rules'] = delete_security_group_rules

        return update

    def _create(self):
        kwargs = dict((k, self.params[k])
                      for k in ['description', 'name', 'stateful']
                      if self.params[k] is not None)

        project_name_or_id = self.params['project']
        if project_name_or_id is not None:
            project = self.conn.identity.find_project(
                name_or_id=project_name_or_id, ignore_missing=False)
            kwargs['project_id'] = project.id

        security_group = self.conn.network.create_security_group(**kwargs)

        update = self._build_update_security_group_rules(security_group)
        if update:
            security_group = self._update_security_group_rules(security_group,
                                                               update)

        return security_group

    def _delete(self, security_group):
        self.conn.network.delete_security_group(security_group.id)

    def _find(self):
        kwargs = dict(name_or_id=self.params['name'])

        project_name_or_id = self.params['project']
        if project_name_or_id is not None:
            project = self.conn.identity.find_project(
                name_or_id=project_name_or_id, ignore_missing=False)
            kwargs['project_id'] = project.id

        return self.conn.network.find_security_group(**kwargs)

    def _generate_security_group_rules(self, security_group):
        security_group_cache = {}
        security_group_cache[security_group.name] = security_group
        security_group_cache[security_group.id] = security_group

        def _generate_security_group_rule(params):
            prototype = dict(
                (k, params[k])
                for k in ['description', 'direction', 'remote_ip_prefix']
                if params[k] is not None)

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

            prototype['project_id'] = security_group.project_id
            prototype['security_group_id'] = security_group.id

            remote_group_name_or_id = params['remote_group']
            if remote_group_name_or_id is not None:
                if remote_group_name_or_id in security_group_cache:
                    remote_group = \
                        security_group_cache[remote_group_name_or_id]
                else:
                    remote_group = self.conn.network.find_security_group(
                        remote_group_name_or_id, ignore_missing=False)
                    security_group_cache[remote_group_name_or_id] = \
                        remote_group

                prototype['remote_group_id'] = remote_group.id

            ether_type = params['ether_type']
            if ether_type is not None:
                prototype['ether_type'] = ether_type

            protocol = params['protocol']
            if protocol is not None and protocol not in ['any', '0']:
                prototype['protocol'] = protocol

            port_range_max = params['port_range_max']
            port_range_min = params['port_range_min']

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

        return [_generate_security_group_rule(r)
                for r in (self.params['security_group_rules'] or [])]

    def _update(self, security_group, update):
        security_group = self._update_security_group(security_group, update)
        return self._update_security_group_rules(security_group, update)

    def _update_security_group(self, security_group, update):
        attributes = update.get('attributes')
        if attributes:
            security_group = self.conn.network.update_security_group(
                security_group.id, **attributes)

        return security_group

    def _update_security_group_rules(self, security_group, update):
        delete_security_group_rules = update.get('delete_security_group_rules')
        if delete_security_group_rules:
            for security_group_rule in delete_security_group_rules:
                self.conn.network.\
                    delete_security_group_rule(security_group_rule['id'])

        create_security_group_rules = update.get('create_security_group_rules')
        if create_security_group_rules:
            self.conn.network.\
                create_security_group_rules(create_security_group_rules)

        if create_security_group_rules or delete_security_group_rules:
            # Update security group with created and deleted rules
            return self.conn.network.get_security_group(security_group.id)
        else:
            return security_group

    def _will_change(self, state, security_group):
        if state == 'present' and not security_group:
            return True
        elif state == 'present' and security_group:
            return bool(self._build_update(security_group))
        elif state == 'absent' and security_group:
            return True
        else:
            # state == 'absent' and not security_group:
            return False


def main():
    module = SecurityGroupModule()
    module()


if __name__ == '__main__':
    main()
