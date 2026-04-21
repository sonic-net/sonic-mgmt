#!/usr/bin/python
# Copyright (c) 2018-2019 Red Hat, Inc.
# Copyright (c) 2020 Infoblox, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: nios_dtc_pool
author: "Mauricio Teixeira (@badnetmask)"
version_added: "1.1.0"
short_description: Configure Infoblox NIOS DTC Pool
description:
  - Adds and/or removes instances of DTC Pool objects from
    Infoblox NIOS servers. This module manages NIOS C(dtc:pool) objects
    using the Infoblox WAPI interface over REST. A DTC pool is a collection
    of IDNS resources (virtual servers).
requirements:
  - infoblox-client
extends_documentation_fragment: infoblox.nios_modules.nios
notes:
    - This module supports C(check_mode).
options:
  name:
    description:
      - Specifies the DTC Pool display name
    required: true
    type: str
  lb_preferred_method:
    description:
      - Configures the preferred load balancing method.
      - Use this to select a method type from the pool.
    choices:
      - ALL_AVAILABLE
      - DYNAMIC_RATIO
      - GLOBAL_AVAILABILITY
      - RATIO
      - ROUND_ROBIN
      - TOPOLOGY
    required: true
    type: str
  lb_preferred_topology:
    description:
      - Configures the topology rules for the C(TOPOLOGY) load balancing method.
      - Required only when I(lb_preferred_method) is set to C(TOPOLOGY).
    required: false
    type: str
  servers:
    description:
      - Configure the DTC Servers related to the pool
    required: false
    type: list
    elements: dict
    suboptions:
      server:
        description:
          - Provide the name of the DTC Server
        required: true
        type: str
      ratio:
        description:
          - Provide the weight of the server
        default: 1
        required: false
        type: int
  monitors:
    description:
      - Specifies the health monitors related to pool.
      - The format of this parameter is required due to an API
        limitation.
      - This option only works if you set the C(wapi_version)
        variable on your C(provider) variable to a number higher
        than "2.6".
    required: false
    type: list
    elements: dict
    suboptions:
      name:
        description:
          - Provide the name of the health monitor.
        required: true
        type: str
      type:
        description:
          - Provide the type of health monitor.
        choices:
          - http
          - icmp
          - tcp
          - pdp
          - sip
          - snmp
        required: true
        type: str
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
- name: Configure a DTC Pool
  infoblox.nios_modules.nios_dtc_pool:
    name: web_pool
    lb_preferred_method: ROUND_ROBIN
    servers:
      - server: a.ansible.com
      - server: b.ansible.com
    state: present
    provider:
      host: "{{ inventory_hostname_short }}"
      username: admin
      password: admin
  connection: local

- name: Add a comment to a DTC Pool
  infoblox.nios_modules.nios_dtc_pool:
    name: web_pool
    lb_preferred_method: ROUND_ROBIN
    comment: this is a test comment
    state: present
    provider:
      host: "{{ inventory_hostname_short }}"
      username: admin
      password: admin
  connection: local

- name: Remove a DTC Pool from the system
  infoblox.nios_modules.nios_dtc_pool:
    name: web_pool
    lb_preferred_method: ROUND_ROBIN
    state: absent
    provider:
      host: "{{ inventory_hostname_short }}"
      username: admin
      password: admin
  connection: local
'''

RETURN = ''' # '''

from ..module_utils.api import NIOS_DTC_POOL
from ..module_utils.api import WapiModule
from ..module_utils.api import normalize_ib_spec
from ansible.module_utils.basic import AnsibleModule


def main():
    ''' Main entry point for module execution
    '''

    def servers_transform(module):
        server_list = list()
        if module.params['servers']:
            for server in module.params['servers']:
                server_obj = wapi.get_object('dtc:server',
                                             {'name': server['server']})
                if server_obj:
                    server_list.append({'server': server_obj[0]['_ref'],
                                        'ratio': server['ratio']})
                else:
                    module.fail_json(msg='Server %s cannot be found.' % server)
        return server_list

    def monitors_transform(module):
        monitor_list = list()
        if module.params['monitors']:
            for monitor in module.params['monitors']:
                monitor_obj = wapi.get_object('dtc:monitor:' + monitor['type'],
                                              {'name': monitor['name']})
                if monitor_obj:
                    monitor_list.append(monitor_obj[0]['_ref'])
                else:
                    module.fail_json(
                        msg='monitor %s cannot be found.' % monitor)
        return monitor_list

    def topology_transform(module):
        topology = module.params['lb_preferred_topology']
        if topology:
            topo_obj = wapi.get_object('dtc:topology', {'name': topology})
            if topo_obj:
                return topo_obj[0]['_ref']
            else:
                module.fail_json(
                    msg='topology %s cannot be found.' % topology)

    servers_spec = dict(
        server=dict(required=True),
        ratio=dict(type='int', default=1)
    )

    monitors_spec = dict(
        name=dict(required=True),
        type=dict(required=True, choices=['http', 'icmp', 'tcp', 'pdp', 'sip', 'snmp'])
    )

    ib_spec = dict(
        name=dict(required=True, ib_req=True),
        lb_preferred_method=dict(required=True, choices=['ALL_AVAILABLE',
                                                         'DYNAMIC_RATIO',
                                                         'GLOBAL_AVAILABILITY',
                                                         'RATIO',
                                                         'ROUND_ROBIN',
                                                         'TOPOLOGY']),
        lb_preferred_topology=dict(type='str', transform=topology_transform),

        servers=dict(type='list', elements='dict', options=servers_spec,
                     transform=servers_transform),
        monitors=dict(type='list', elements='dict', options=monitors_spec,
                      transform=monitors_transform),

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
    result = wapi.run(NIOS_DTC_POOL, ib_spec)

    module.exit_json(**result)


if __name__ == '__main__':
    main()
