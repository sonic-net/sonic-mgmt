#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2016 Hewlett-Packard Enterprise
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: dns_zone
short_description: Manage a OpenStack DNS zone.
author: OpenStack Ansible SIG
description:
    - Create, delete or update a OpenStack DNS zone.
options:
  description:
    description:
      - Zone description.
    type: str
  email:
    description:
      - Email of the zone owner.
      - Only applies if I(type) is C(primary).
    type: str
  masters:
    description:
      - Master nameservers
      - Only applies if I(type) is C(secondary).
    type: list
    elements: str
  name:
    description:
      - Name of the DNS zone.
    required: true
    type: str
  state:
    description:
      - Whether the zone should be C(present) or C(absent).
    choices: ['present', 'absent']
    default: present
    type: str
  ttl:
    description:
      -  TTL (Time To Live) value in seconds.
    type: int
  type:
    description:
      - Zone type.
      - This attribute cannot be updated.
    choices: ['primary', 'secondary']
    type: str
    aliases: ['zone_type']
extends_documentation_fragment:
  - openstack.cloud.openstack
'''

EXAMPLES = r'''
- name: Create DNS zone example.net.
  openstack.cloud.dns_zone:
    cloud: mycloud
    state: present
    name: example.net.
    type: primary
    email: test@example.net
    description: Test zone
    ttl: 3600

- name: Set TTL on DNS zone example.net.
  openstack.cloud.dns_zone:
    cloud: mycloud
    state: present
    name: example.net.
    ttl: 7200

- name: Delete zone example.net.
  openstack.cloud.dns_zone:
    cloud: mycloud
    state: absent
    name: example.net.
'''

RETURN = r'''
zone:
  description: Dictionary describing the zone.
  returned: On success when I(state) is C(present).
  type: dict
  contains:
    action:
      description: Current action in progress on the resource.
      type: str
      sample: "CREATE"
    attributes:
      description: Key value pairs of information about this zone, and the
                   pool the user would like to place the zone in. This
                   information can be used by the scheduler to place zones on
                   the correct pool.
      type: dict
      sample: {"tier": "gold", "ha": "true"}
    created_at:
      description: Date / Time when resource was created.
      type: str
      sample: "2014-07-07T18:25:31.275934"
    description:
      description: Description for this zone.
      type: str
      sample: "This is an example zone."
    email:
      description: E-mail for the zone. Used in SOA records for the zone.
      type: str
      sample: "test@example.org"
    id:
      description: ID for the resource.
      type: int
      sample: "a86dba58-0043-4cc6-a1bb-69d5e86f3ca3"
    links:
      description: Links to the resource, and other related resources. When a
                   response has been broken into pages, we will include a next
                   link that should be followed to retrieve all results.
      type: dict
      sample: {"self": "https://127.0.0.1:9001/v2/zones/a86dba...d5e86f3ca3"}
    masters:
      description: The servers to slave from to get DNS information.
                   Mandatory for secondary zones.
      type: list
      sample: "[]"
    name:
      description: DNS Name for the zone.
      type: str
      sample: "test.test."
    pool_id:
      description: ID for the pool hosting this zone.
      type: str
      sample: "a86dba58-0043-4cc6-a1bb-69d5e86f3ca3"
    project_id:
      description: ID for the project that owns the resource.
      type: str
      sample: "4335d1f0-f793-11e2-b778-0800200c9a66"
    serial:
      description: Current serial number for the zone.
      type: int
      sample: 1404757531
    status:
      description: Status of the resource.
      type: str
      sample: "ACTIVE"
    ttl:
      description: TTL (Time to Live) for the zone.
      type: int
      sample: 7200
    type:
      description: Type of zone. PRIMARY is controlled by Designate,
                   SECONDARY zones are slaved from another DNS Server.
                   Defaults to PRIMARY.
      type: str
      sample: "PRIMARY"
    updated_at:
      description: Date / Time when resource last updated.
      type: str
      sample: "2014-07-07T18:25:31.275934"
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import OpenStackModule


class DnsZoneModule(OpenStackModule):

    argument_spec = dict(
        description=dict(),
        email=dict(),
        masters=dict(type='list', elements='str'),
        name=dict(required=True),
        state=dict(default='present', choices=['absent', 'present']),
        ttl=dict(type='int'),
        type=dict(choices=['primary', 'secondary'], aliases=['zone_type']),
    )

    def run(self):
        state = self.params['state']
        name_or_id = self.params['name']

        zone = self.conn.dns.find_zone(name_or_id=name_or_id)

        if self.ansible.check_mode:
            self.exit_json(changed=self._will_change(state, zone))

        if state == 'present' and not zone:
            # Create zone
            zone = self._create()
            self.exit_json(changed=True,
                           zone=zone.to_dict(computed=False))

        elif state == 'present' and zone:
            # Update zone
            update = self._build_update(zone)
            if update:
                zone = self._update(zone, update)

            self.exit_json(changed=bool(update),
                           zone=zone.to_dict(computed=False))

        elif state == 'absent' and zone:
            # Delete zone
            self._delete(zone)
            self.exit_json(changed=True)

        elif state == 'absent' and not zone:
            # Do nothing
            self.exit_json(changed=False)

    def _build_update(self, zone):
        update = {}

        attributes = dict((k, self.params[k])
                          for k in ['description', 'email', 'masters', 'ttl']
                          if self.params[k] is not None
                          and self.params[k] != zone[k])

        if attributes:
            update['attributes'] = attributes

        return update

    def _create(self):
        kwargs = dict((k, self.params[k])
                      for k in ['description', 'email', 'masters', 'name',
                                'ttl', 'type']
                      if self.params[k] is not None)

        if 'type' in kwargs:
            # designate expects upper case PRIMARY or SECONDARY
            kwargs['type'] = kwargs['type'].upper()

        zone = self.conn.dns.create_zone(**kwargs)

        if self.params['wait']:
            self.sdk.resource.wait_for_status(
                self.conn.dns, zone,
                status='active',
                failures=['error'],
                wait=self.params['timeout'])

        return zone

    def _delete(self, zone):
        self.conn.dns.delete_zone(zone.id)

        for count in self.sdk.utils.iterate_timeout(
            timeout=self.params['timeout'],
            message="Timeout waiting for zone to be absent"
        ):
            if self.conn.dns.find_zone(zone.id) is None:
                break

    def _update(self, zone, update):
        attributes = update.get('attributes')
        if attributes:
            zone = self.conn.dns.update_zone(zone.id, **attributes)

        if self.params['wait']:
            self.sdk.resource.wait_for_status(
                self.conn.dns, zone,
                status='active',
                failures=['error'],
                wait=self.params['timeout'])

        return zone

    def _will_change(self, state, zone):
        if state == 'present' and not zone:
            return True
        elif state == 'present' and zone:
            return bool(self._build_update(zone))
        elif state == 'absent' and zone:
            return True
        else:
            # state == 'absent' and not zone:
            return False


def main():
    module = DnsZoneModule()
    module()


if __name__ == '__main__':
    main()
