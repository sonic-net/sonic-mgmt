#!/usr/bin/python
# Copyright (c) 2018-2019 Red Hat, Inc.
# Copyright (c) 2020 Infoblox, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: nios_dtc_monitor_icmp
author: "Joachim Buyse (@jbisabel)"
version_added: "1.6.0"
short_description: Configure Infoblox NIOS DTC ICMP monitors
description:
  - Adds and/or removes instances of DTC ICMP monitor objects from Infoblox NIOS
    servers. This module manages C(dtc:monitor:icmp) objects using the Infoblox
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
  interval:
    description:
      - Configures the interval for ICMP health check.
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
      - Configures the timeout for ICMP health check in seconds.
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
- name: Configure a DTC ICMP monitor
  infoblox.nios_modules.nios_dtc_monitor_icmp:
    name: icmp_monitor
    port: 8080
    state: present
    provider:
      host: "{{ inventory_hostname_short }}"
      username: admin
      password: admin
  connection: local

- name: Add a comment to an existing DTC ICMP monitor
  infoblox.nios_modules.nios_dtc_monitor_icmp:
    name: icmp_monitor
    comment: this is a test comment
    state: present
    provider:
      host: "{{ inventory_hostname_short }}"
      username: admin
      password: admin
  connection: local

- name: Remove a DTC ICMP monitor from the system
  infoblox.nios_modules.nios_dtc_monitor_icmp:
    name: icmp_monitor
    state: absent
    provider:
      host: "{{ inventory_hostname_short }}"
      username: admin
      password: admin
  connection: local
'''

RETURN = ''' # '''

from ansible.module_utils.basic import AnsibleModule
from ..module_utils.api import WapiModule
from ..module_utils.api import NIOS_DTC_MONITOR_ICMP
from ..module_utils.api import normalize_ib_spec


def main():
    ''' Main entry point for module execution
    '''

    ib_spec = dict(
        name=dict(required=True, ib_req=True),

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
    result = wapi.run(NIOS_DTC_MONITOR_ICMP, ib_spec)

    module.exit_json(**result)


if __name__ == '__main__':
    main()
