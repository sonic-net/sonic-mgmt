#!/usr/bin/python
# Copyright (c) 2018-2019 Red Hat, Inc.
# Copyright (c) 2020 Infoblox, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: nios_dtc_lbdn
author: "Mauricio Teixeira (@badnetmask)"
version_added: "1.1.0"
short_description: Configure Infoblox NIOS DTC LBDN
description:
  - Adds and/or removes instances of DTC Load Balanced Domain Name (LBDN)
    objects from Infoblox NIOS servers. This module manages NIOS
    C(dtc:lbdn) objects using the Infoblox WAPI interface over REST.
requirements:
  - infoblox-client
extends_documentation_fragment: infoblox.nios_modules.nios
notes:
    - This module supports C(check_mode).
options:
  name:
    description:
      - Specifies the display name of the DTC LBDN, not DNS related.
    required: true
    type: str
  lb_method:
    description:
      - Configures the load balancing method. Used to select pool.
    required: true
    type: str
    choices:
      - GLOBAL_AVAILABILITY
      - RATIO
      - ROUND_ROBIN
      - TOPOLOGY
  topology:
    description:
      - Configures the topology rules for the C(TOPOLOGY) load balancing method.
      - Required only when I(lb_method) is set to C(TOPOLOGY).
    required: false
    type: str
  auth_zones:
    description:
      - List of linked authoritative zones.
      - When using I(auth_zones), you must specify at least one
        I(patterns)
    required: false
    type: list
    elements: str
  patterns:
    description:
      - Specify LBDN wildcards for pattern match.
    required: false
    type: list
    elements: str
  types:
    description:
      - Specifies the list of resource record types supported by LBDN.
      - This option will work properly only if you set the C(wapi_version)
        variable on your C(provider) variable to a
        number higher than "2.6".
    required: false
    type: list
    elements: str
    choices:
      - A
      - AAAA
      - CNAME
      - NAPTR
      - SRV
  pools:
    description:
      - The pools used for load balancing.
    required: false
    type: list
    elements: dict
    suboptions:
      pool:
        description:
          - Provide the name of the pool to link with
        required: true
        type: str
      ratio:
        description:
          - Provide the weight of the pool
        default: 1
        required: false
        type: int
  ttl:
    description:
      - The Time To Live (TTL) value for the DTC LBDN. A 32-bit unsigned
        integer that represents the duration, in seconds, for which the
        record is valid (cached). Zero indicates that the record should
        not be cached.
    type: int
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
        the NIOS server.  When this value is set to C(present), the object
        is configured on the device and when this value is set to C(absent)
        the value is removed (if necessary) from the device.
    default: present
    choices:
      - present
      - absent
    type: str
'''

EXAMPLES = '''
- name: Configure a DTC LBDN
  infoblox.nios_modules.nios_dtc_lbdn:
    name: web.ansible.com
    lb_method: ROUND_ROBIN
    pools:
      - pool: web_pool
    state: present
    provider:
      host: "{{ inventory_hostname_short }}"
      username: admin
      password: admin
  connection: local

- name: Add a comment to a DTC LBDN
  infoblox.nios_modules.nios_dtc_lbdn:
    name: web.ansible.com
    lb_method: ROUND_ROBIN
    comment: this is a test comment
    state: present
    provider:
      host: "{{ inventory_hostname_short }}"
      username: admin
      password: admin
  connection: local

- name: Remove a DTC LBDN from the system
  infoblox.nios_modules.nios_dtc_lbdn:
    name: web.ansible.com
    lb_method: ROUND_ROBIN
    state: absent
    provider:
      host: "{{ inventory_hostname_short }}"
      username: admin
      password: admin
  connection: local
'''

RETURN = ''' # '''

from ..module_utils.api import NIOS_DTC_LBDN
from ..module_utils.api import WapiModule
from ..module_utils.api import normalize_ib_spec
from ansible.module_utils.basic import AnsibleModule


def main():
    ''' Main entry point for module execution
    '''

    def auth_zones_transform(module):
        zone_list = list()
        if module.params['auth_zones']:
            for zone in module.params['auth_zones']:
                zone_obj = wapi.get_object('zone_auth',
                                           {'fqdn': zone})
                if zone_obj:
                    zone_list.append(zone_obj[0]['_ref'])
                else:
                    module.fail_json(
                        msg='auth_zone %s cannot be found.' % zone)
        return zone_list

    def pools_transform(module):
        pool_list = list()
        if module.params['pools']:
            for pool in module.params['pools']:
                pool_obj = wapi.get_object('dtc:pool',
                                           {'name': pool['pool']})
                if 'ratio' not in pool:
                    pool['ratio'] = 1
                if pool_obj:
                    pool_list.append({'pool': pool_obj[0]['_ref'],
                                      'ratio': pool['ratio']})
                else:
                    module.fail_json(msg='pool %s cannot be found.' % pool)
        return pool_list

    def topology_transform(module):
        topology = module.params['topology']
        if topology:
            topo_obj = wapi.get_object('dtc:topology', {'name': topology})
            if topo_obj:
                return topo_obj[0]['_ref']
            else:
                module.fail_json(
                    msg='topology %s cannot be found.' % topology)

    auth_zones_spec = dict()

    pools_spec = dict(
        pool=dict(required=True),
        ratio=dict(type='int', default=1)
    )

    ib_spec = dict(
        name=dict(required=True, ib_req=True),
        lb_method=dict(required=True, choices=['GLOBAL_AVAILABILITY',
                                               'RATIO', 'ROUND_ROBIN', 'TOPOLOGY']),

        topology=dict(type='str', transform=topology_transform),
        auth_zones=dict(type='list', elements='str', options=auth_zones_spec,
                        transform=auth_zones_transform),
        patterns=dict(type='list', elements='str'),
        types=dict(type='list', elements='str', choices=['A', 'AAAA', 'CNAME', 'NAPTR',
                                                         'SRV']),
        pools=dict(type='list', elements='dict', options=pools_spec,
                   transform=pools_transform),
        ttl=dict(type='int'),

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
    result = wapi.run(NIOS_DTC_LBDN, ib_spec)

    module.exit_json(**result)


if __name__ == '__main__':
    main()
