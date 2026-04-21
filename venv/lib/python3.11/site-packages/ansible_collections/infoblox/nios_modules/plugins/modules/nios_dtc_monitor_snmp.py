#!/usr/bin/python
# Copyright (c) 2018-2019 Red Hat, Inc.
# Copyright (c) 2020 Infoblox, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: nios_dtc_monitor_snmp
author: "Joachim Buyse (@jbisabel)"
version_added: "1.6.0"
short_description: Configure Infoblox NIOS DTC SNMP monitors
description:
  - Adds and/or removes instances of DTC SNMP monitor objects from Infoblox NIOS
    servers. This module manages C(dtc:monitor:snmp) objects using the Infoblox
    WAPI interface over REST.
requirements:
  - infoblox-client
extends_documentation_fragment: infoblox.nios_modules.nios
notes:
    - This module supports C(check_mode).
options:
  name:
    description:
      - Configures the display name for this DTC monitor. Values with leading
        or trailing white space are not valid for this field.
    required: true
    type: str
  port:
    description:
      - Configures the port value for SNMP requests.
    type: int
    default: 161
  version:
    description:
      - Configures the SNMP protocol version for the SNMP health check.
    type: str
    choices:
      - V1
      - V2C
      - V3
    default: V2C
  community:
    description:
      - Configures the SNMP community string for SNMP authentication.
    type: str
    default: public
  user:
    description:
      - Configures the SNMPv3 user setting.
    type: str
  context:
    description:
      - Configures the SNMPv3 context. Values with leading or trailing white
        space are not valid for this field.
    type: str
  engine_id:
    description:
      - Configures the SNMPv3 engine identifier. Values with leading or
        trailing white space are not valid for this field.
    type: str
  oids:
    description:
      - Configures the list of OIDs for SNMP monitoring.
    type: list
    elements: dict
    suboptions:
      comment:
        description:
          - Configures a text string comment to be associated with the instance
            of this object.  The provided text string will be configured on the
            object instance.
        type: str
      condition:
        description:
          - Configures the condition of the validation result for the SNMP
            health check.
        type: str
        choices:
          - ANY
          - EXACT
          - GEQ
          - LEQ
          - RANGE
        default: ANY
      first:
        description:
          - Configures the condition's first term to match against the SNMP
            health check result.
        type: str
      last:
        description:
          - Configures the condition's second term to match against the SNMP
            health check result with 'RANGE' condition.
        type: str
      oid:
        description:
          - Configures the SNMP OID value for DTC SNMP Monitor health checks.
          - This field is required on creation
        required: true
        type: str
      type:
        description:
          - Configures the condition type for DTC SNMP Monitor health checks
            results.
        type: str
        choices:
          - INTEGER
          - STRING
        default: STRING
  interval:
    description:
      - Configures the interval for SNMP health check.
    type: int
    default: 5
  retry_down:
    description:
      - Configures the value of how many times the server should appear as
        down to be treated as dead after it was alive.
    type: int
    default: 1
  retry_up:
    description:
      - Configures the value of how many times the server should appear as up
        to be treated as alive after it was dead.
    type: int
    default: 1
  timeout:
    description:
      - Configures the timeout for SNMP health check in seconds.
    type: int
    default: 15
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
- name: Configure a DTC SNMP monitor
  infoblox.nios_modules.nios_dtc_monitor_snmp:
    name: snmp_monitor
    port: 8080
    state: present
    provider:
      host: "{{ inventory_hostname_short }}"
      username: admin
      password: admin
  connection: local

- name: Add a comment to an existing DTC SNMP monitor
  infoblox.nios_modules.nios_dtc_monitor_snmp:
    name: snmp_monitor
    comment: this is a test comment
    state: present
    provider:
      host: "{{ inventory_hostname_short }}"
      username: admin
      password: admin
  connection: local

- name: Remove a DTC SNMP monitor from the system
  infoblox.nios_modules.nios_dtc_monitor_snmp:
    name: snmp_monitor
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
from ..module_utils.api import NIOS_DTC_MONITOR_SNMP
from ..module_utils.api import normalize_ib_spec


def oids(module):
    ''' Transform the module argument into a valid WAPI struct
    This function will transform the oids argument into a structure that is a
    valid WAPI structure in the format of:
        {
            comment: <value>,
            condition: <value>,
            first: <value>,
            last: <value>,
            oid: <value>,
            type: <value>,
        }
    It will remove any options that are set to None since WAPI will error on
    that condition.
    The remainder of the value validation is performed by WAPI
    '''

    oids = list()
    for item in module.params['oids']:
        oid = dict([(k, v) for k, v in iteritems(item) if v is not None])
        if 'oid' not in oid:
            module.fail_json(msg='oid is required for oid value')
        oids.append(oid)
    return oids


def main():
    ''' Main entry point for module execution
    '''

    oid_spec = dict(
        comment=dict(type='str'),
        condition=dict(default='ANY', choices=['ANY', 'EXACT', 'GEQ', 'LEQ', 'RANGE']),
        first=dict(type='str'),
        last=dict(type='str'),
        oid=dict(type='str', required=True),
        type=dict(default='STRING', choices=['INTEGER', 'STRING'])
    )

    ib_spec = dict(
        name=dict(required=True, ib_req=True),

        port=dict(type='int', default=161),
        version=dict(default='V2C', choices=['V1', 'V2C', 'V3']),
        community=dict(type='str', default='public'),
        user=dict(type='str'),
        context=dict(type='str'),
        engine_id=dict(type='str'),
        oids=dict(type='list', elements='dict', options=oid_spec, transform=oids),
        interval=dict(type='int', default=5),
        retry_down=dict(type='int', default=1),
        retry_up=dict(type='int', default=1),
        timeout=dict(type='int', default=15),

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
    result = wapi.run(NIOS_DTC_MONITOR_SNMP, ib_spec)

    module.exit_json(**result)


if __name__ == '__main__':
    main()
