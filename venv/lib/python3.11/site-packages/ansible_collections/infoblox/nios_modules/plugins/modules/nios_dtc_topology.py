#!/usr/bin/python
# Copyright (c) 2018-2019 Red Hat, Inc.
# Copyright (c) 2020 Infoblox, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: nios_dtc_topology
author: "Joachim Buyse (@jbisabel)"
short_description: Configure Infoblox NIOS DTC Topology
version_added: "1.6.0"
description:
  - Adds and/or removes instances of DTC Topology objects from
    Infoblox NIOS topologies. This module manages NIOS C(dtc:topology) objects
    using the Infoblox WAPI interface over REST.
requirements:
  - infoblox-client
extends_documentation_fragment: infoblox.nios_modules.nios
notes:
    - This module supports C(check_mode).
options:
  name:
    description:
      - Specifies the DTC Topology display name.
    required: true
    type: str
  rules:
    description:
      - Configures the topology rules
    type: list
    elements: dict
    suboptions:
      dest_type:
        description:
          - Configures the type of the destination for this DTC Topology Rule.
        type: str
        choices:
          - POOL
          - SERVER
        required: true
      destination_link:
        description:
          - Configures the name of the destination DTC pool or DTC server.
        type: str
      return_type:
        description:
          - Configures the type of the DNS response for the rule.
        type: str
        choices:
          - NOERR
          - NXDOMAIN
          - REGULAR
        default: REGULAR
      sources:
        description:
          - Configures the conditions for matching sources. Should be empty to
            set the rule as default destination.
        type: list
        elements: dict
        suboptions:
          source_op:
            description:
              - Configures the operation used to match the value.
            type: str
            choices:
              - IS
              - IS_NOT
          source_type:
            description:
              - Configures the source type.
            type: str
            choices:
              - CITY
              - CONTINENT
              - COUNTRY
              - EA0
              - EA1
              - EA2
              - EA3
              - SUBDIVISION
              - SUBNET
            required: true
          source_value:
            description:
              - Configures the source value.
            type: str
            required: true
  extattrs:
    description:
      - Allows for the configuration of Extensible Attributes on the
        instance of the object.  This argument accepts a set of key / value
        pairs for configuration.
    type: dict
  comment:
    description:
      - Configures a text string comment to be associated with the instance
        of this object.  The provided text string will be configured on the
        object instance.
    type: str
  state:
    description:
      - Configures the intended state of the instance of the object on
        the NIOS topology.  When this value is set to C(present), the object
        is configured on the device and when this value is set to C(absent)
        the value is removed (if necessary) from the device.
    default: present
    choices:
      - present
      - absent
    type: str
'''

EXAMPLES = '''
- name: Configure a DTC Topology
  infoblox.nios_modules.nios_dtc_topology:
    name: a_topology
    rules:
      - dest_type: POOL
        destination_link: web_pool1
        return_type: REGULAR
        sources:
          - source_op: IS
            source_type: EA0
            source_value: DC1
      - dest_type: POOL
        destination_link: web_pool2
        return_type: REGULAR
        sources:
          - source_op: IS
            source_type: EA0
            source_value: DC2
    state: present
    provider:
      host: "{{ inventory_hostname_short }}"
      username: admin
      password: admin
  connection: local

- name: Add a comment to a DTC topology
  infoblox.nios_modules.nios_dtc_topology:
    name: a_topology
    comment: this is a test comment
    state: present
    provider:
      host: "{{ inventory_hostname_short }}"
      username: admin
      password: admin
  connection: local

- name: Remove a DTC Topology from the system
  infoblox.nios_modules.nios_dtc_topology:
    name: a_topology
    state: absent
    provider:
      host: "{{ inventory_hostname_short }}"
      username: admin
      password: admin
  connection: local
'''

RETURN = ''' # '''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.six import iteritems
from ..module_utils.api import WapiModule
from ..module_utils.api import NIOS_DTC_TOPOLOGY
from ..module_utils.api import normalize_ib_spec


def main():
    ''' Main entry point for module execution
    '''

    def sources_transform(sources, module):
        source_list = list()
        for source in sources:
            src = dict([(k, v) for k, v in iteritems(source) if v is not None])
            if 'source_type' not in src or 'source_value' not in src:
                module.fail_json(msg='source_type and source_value are required for source')
            source_list.append(src)
        return source_list

    def rules_transform(module):
        rule_list = list()
        dest_obj = None

        if not module.params['rules']:
            return rule_list

        for rule in module.params['rules']:
            if rule['dest_type'] == 'POOL':
                dest_obj = wapi.get_object('dtc:pool', {'name': rule['destination_link']})
            else:
                dest_obj = wapi.get_object('dtc:server', {'name': rule['destination_link']})
            if not dest_obj and rule['return_type'] == 'REGULAR':
                module.fail_json(msg='destination_link %s does not exist' % rule['destination_link'])

            tf_rule = dict(
                dest_type=rule['dest_type'],
                destination_link=dest_obj[0]['_ref'] if dest_obj else None,
                return_type=rule['return_type']
            )

            if rule['sources']:
                tf_rule['sources'] = sources_transform(rule['sources'], module)

            rule_list.append(tf_rule)
        return rule_list

    source_spec = dict(
        source_op=dict(choices=['IS', 'IS_NOT']),
        source_type=dict(required=True, choices=['CITY', 'CONTINENT', 'COUNTRY', 'EA0', 'EA1', 'EA2', 'EA3', 'SUBDIVISION', 'SUBNET']),
        source_value=dict(required=True, type='str')
    )

    rule_spec = dict(
        dest_type=dict(required=True, choices=['POOL', 'SERVER']),
        destination_link=dict(type='str'),
        return_type=dict(default='REGULAR', choices=['NOERR', 'NXDOMAIN', 'REGULAR']),
        sources=dict(type='list', elements='dict', options=source_spec)
    )

    ib_spec = dict(
        name=dict(required=True, ib_req=True),

        rules=dict(type='list', elements='dict', options=rule_spec, transform=rules_transform),

        extattrs=dict(type='dict'),
        comment=dict(),
    )

    argument_spec = dict(
        provider=dict(required=True),
        state=dict(default='present', choices=['present', 'absent'])
    )

    argument_spec.update(normalize_ib_spec(ib_spec))
    argument_spec.update(WapiModule.provider_spec)

    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True)

    wapi = WapiModule(module)
    result = wapi.run(NIOS_DTC_TOPOLOGY, ib_spec)

    module.exit_json(**result)


if __name__ == '__main__':
    main()
