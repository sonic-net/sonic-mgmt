#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2016 Hewlett-Packard Enterprise
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = '''
---
module: recordset
short_description: Manage OpenStack DNS recordsets
author: OpenStack Ansible SIG
description:
    - Manage OpenStack DNS recordsets. Recordsets can be created, deleted or
      updated. Only the I(records), I(description), and I(ttl) values
      can be updated.
options:
   description:
     description:
        - Description of the recordset
     type: str
   name:
     description:
        - Name of the recordset. It must be ended with name of dns zone.
     required: true
     type: str
   records:
     description:
        - List of recordset definitions.
        - Required when I(state=present).
     type: list
     elements: str
   recordset_type:
     description:
        - Recordset type
        - Required when I(state=present).
     choices: ['a', 'aaaa', 'mx', 'cname', 'txt', 'ns', 'srv', 'ptr', 'caa']
     type: str
   state:
     description:
       - Should the resource be present or absent.
     choices: [present, absent]
     default: present
     type: str
   ttl:
     description:
        -  TTL (Time To Live) value in seconds
     type: int
   zone:
     description:
        - Name or ID of the zone which manages the recordset
     required: true
     type: str
extends_documentation_fragment:
- openstack.cloud.openstack
'''

EXAMPLES = '''
# Create a recordset named "www.example.net."
- openstack.cloud.recordset:
    cloud: mycloud
    state: present
    zone: example.net.
    name: www.example.net.
    recordset_type: "a"
    records: ['10.1.1.1']
    description: test recordset
    ttl: 3600

# Update the TTL on existing "www.example.net." recordset
- openstack.cloud.recordset:
    cloud: mycloud
    state: present
    zone: example.net.
    name: www.example.net.
    recordset_type: "a"
    records: ['10.1.1.1']
    ttl: 7200

# Delete recordset named "www.example.net."
- openstack.cloud.recordset:
    cloud: mycloud
    state: absent
    zone: example.net.
    name: www.example.net.
'''

RETURN = '''
recordset:
    description: Dictionary describing the recordset.
    returned: On success when I(state) is 'present'.
    type: dict
    contains:
        action:
            description: Current action in progress on the resource
            type: str
            returned: always
        created_at:
            description: Timestamp when the zone was created
            type: str
            returned: always
        description:
            description: Recordset description
            type: str
            sample: "Test description"
            returned: always
        id:
            description: Unique recordset ID
            type: str
            sample: "c1c530a3-3619-46f3-b0f6-236927b2618c"
        links:
            description: Links related to the resource
            type: dict
            returned: always
        name:
            description: Recordset name
            type: str
            sample: "www.example.net."
            returned: always
        project_id:
            description: ID of the proect to which the recordset belongs
            type: str
            returned: always
        records:
            description: Recordset records
            type: list
            sample: ['10.0.0.1']
            returned: always
        status:
            description:
                - Recordset status
                - Valid values include `PENDING_CREATE`, `ACTIVE`,`PENDING_DELETE`,
                  `ERROR`
            type: str
            returned: always
        ttl:
            description: Zone TTL value
            type: int
            sample: 3600
            returned: always
        type:
            description:
                - Recordset type
                - Valid values include `A`, `AAAA`, `MX`, `CNAME`, `TXT`, `NS`,
                  `SSHFP`, `SPF`, `SRV`, `PTR`
            type: str
            sample: "A"
            returned: always
        zone_id:
            description: The id of the Zone which this recordset belongs to
            type: str
            sample: 9508e177-41d8-434e-962c-6fe6ca880af7
            returned: always
        zone_name:
            description: The name of the Zone which this recordset belongs to
            type: str
            sample: "example.com."
            returned: always
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import OpenStackModule


class DnsRecordsetModule(OpenStackModule):
    argument_spec = dict(
        description=dict(),
        name=dict(required=True),
        records=dict(type='list', elements='str'),
        recordset_type=dict(choices=['a', 'aaaa', 'mx', 'cname', 'txt', 'ns', 'srv', 'ptr', 'caa']),
        state=dict(default='present', choices=['absent', 'present']),
        ttl=dict(type='int'),
        zone=dict(required=True),
    )

    module_kwargs = dict(
        required_if=[
            ('state', 'present',
             ['recordset_type', 'records'])],
        supports_check_mode=True
    )

    module_min_sdk_version = '0.28.0'

    def _needs_update(self, params, recordset):
        if params['records'] is not None:
            params['records'] = sorted(params['records'])
        if recordset['records'] is not None:
            recordset['records'] = sorted(recordset['records'])
        for k in ('description', 'records', 'ttl', 'type'):
            if k not in params:
                continue
            if k not in recordset:
                return True
            if params[k] is not None and params[k] != recordset[k]:
                return True
        return False

    def _system_state_change(self, state, recordset):
        if state == 'present':
            if recordset is None:
                return True
            kwargs = self._build_params()
            return self._needs_update(kwargs, recordset)
        if state == 'absent' and recordset:
            return True
        return False

    def _build_params(self):
        recordset_type = self.params['recordset_type']
        records = self.params['records']
        description = self.params['description']
        ttl = self.params['ttl']
        params = {
            'description': description,
            'records': records,
            'type': recordset_type.upper(),
            'ttl': ttl,
        }
        return {k: v for k, v in params.items() if v is not None}

    def run(self):
        zone = self.params.get('zone')
        name = self.params.get('name')
        state = self.params.get('state')
        ttl = self.params.get('ttl')

        zone = self.conn.dns.find_zone(name_or_id=zone, ignore_missing=False)
        recordset = self.conn.dns.find_recordset(zone, name)

        if self.ansible.check_mode:
            self.exit_json(changed=self._system_state_change(state, recordset))

        changed = False
        if state == 'present':
            kwargs = self._build_params()
            if recordset is None:
                kwargs['ttl'] = ttl or 300
                recordset = self.conn.dns.create_recordset(zone, name=name, **kwargs)
                changed = True
            elif self._needs_update(kwargs, recordset):
                recordset = self.conn.dns.update_recordset(recordset, **kwargs)
                changed = True
            # NOTE(gtema): this is a workaround to temporarily bring the
            # zone_id param back which may not me populated by SDK
            rs = recordset.to_dict(computed=False)
            rs["zone_id"] = zone.id
            self.exit_json(changed=changed, recordset=rs)
        elif state == 'absent' and recordset is not None:
            self.conn.dns.delete_recordset(recordset)
            changed = True
        self.exit_json(changed=changed)


def main():
    module = DnsRecordsetModule()
    module()


if __name__ == '__main__':
    main()
