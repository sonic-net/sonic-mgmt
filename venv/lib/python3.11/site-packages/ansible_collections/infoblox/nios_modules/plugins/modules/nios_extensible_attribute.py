#!/usr/bin/python
# Copyright (c) 2018-2019 Red Hat, Inc.
# Copyright (c) 2020 Infoblox, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: nios_extensible_attribute
author:
  - "Matthew Dennett (@matthewdennett)"
  - "Hugues Malphettes (@hmalphettes)"
short_description: Configure Infoblox NIOS extensible attribute definition
version_added: "1.7.0"
description:
  - Adds and/or removes a extensible attribute definition objects from
    Infoblox NIOS servers.  This module manages NIOS C(extensibleattributedef)
    objects using the Infoblox WAPI interface over REST.
requirements:
  - infoblox-client
extends_documentation_fragment: infoblox.nios_modules.nios
notes:
    - This module supports C(check_mode).
options:
  comment:
    description:
      - Configures a text string comment to be associated with the instance
        of this object. The provided text string will be configured on the
        object instance.
    type: str
  default_value:
    description:
      - Configures the default value which is pre populated in the GUI when
        this attribute is used. Email, URL and string types the value is a
        with a maximum of 256 characters.
    type: str
  list_values:
    description:
      - Configures a list of preset values associated with the instance of this
        object. Only applicable when the attribute type is set to ENUM.
    type: list
    elements: str
  max:
    description:
      - Configures the maximum value to be associated with the instance of
        this object. When provided for an extensible attribute of type
        STRING the value represents the maximum number of characters the string
        can contain. When provided for an extensible attribute of type INTEGER
        the value represents the maximum integer value permitted.Not
        applicable for other attributes types.
    type: int
  min:
    description:
      - Configures the minimum value to be associated with the instance of
        this object. When provided for an extensible attribute of type
        STRING the value represents the minimum number of characters the string
        can contain. When provided for an extensible attribute of type INTEGER
        the value represents the minimum integer value permitted. Not
        applicable for other attributes types.
    type: int
  name:
    description:
      - Configures the intended name of the instance of the object on the
        NIOS server.
    type: str
    required: true
  type:
    description:
      - Configures the intended type for this attribute object definition
        on the NIOS server.
    type: str
    default: STRING
    choices:
      - DATE
      - EMAIL
      - ENUM
      - INTEGER
      - STRING
      - URL
  flags:
    description:
      - This field contains extensible attribute flags.
        The possible values are (A)udited, (C)loud API, Cloud (G)master, (I)nheritable, (L)isted, (M)andatory value,
        MGM (P)rivate, (R)ead Only, (S)ort enum values, Multiple (V)alues.
        If there are two or more flags in the field, you must list them according to the order they are listed above.
        For example, "CR" is a valid value for the "flags" field because C = Cloud API is listed before R = Read only.
        However, the value "RC" is invalid because the order for the "flags" field is broken.
    type: str
  state:
    description:
      - Configures the intended state of the instance of the object on
        the NIOS server.  When this value is set to C(present), the object
        is configured on the device and when this value is set to C(absent)
        the value is removed (if necessary) from the device.
    type: str
    default: present
    choices:
      - present
      - absent
'''

EXAMPLES = '''
- name: Configure an extensible attribute
  infoblox.nios_modules.nios_extensible_attribute:
    name: my_string
    type: STRING
    comment: Created by ansible
    state: present
    provider:
      host: "{{ inventory_hostname_short }}"
      username: admin
      password: admin
  connection: local

- name: Update an extensible attribute to accept multiple values
  infoblox.nios_modules.nios_extensible_attribute:
    name: my_string
    type: STRING
    flags: V
    state: present
    provider:
      host: "{{ inventory_hostname_short }}"
      username: admin
      password: admin
  connection: local

- name: Remove a extensible attribute
  infoblox.nios_modules.nios_extensible_attribute:
    name: my_string
    type: INTEGER
    state: absent
    provider:
      host: "{{ inventory_hostname_short }}"
      username: admin
      password: admin
  connection: local

- name: Create INT extensible attribute
  infoblox.nios_modules.nios_extensible_attribute:
    name: my_int
    type: INTEGER
    comment: Created by ansible
    min: 10
    max: 20
    state: present
    provider:
      host: "{{ inventory_hostname_short }}"
      username: admin
      password: admin
  connection: local

- name: Update an extensible attribute
  infoblox.nios_modules.nios_extensible_attribute:
    name: my_int
    type: INTEGER
    comment: Updated by ansible
    state: present
    provider:
      host: "{{ inventory_hostname_short }}"
      username: admin
      password: admin
  connection: local

- name: Create an list extensible attribute
  infoblox.nios_modules.nios_extensible_attribute:
    name: my_list
    type: ENUM
    state: present
    list_values:
      - one
      - two
      - three
    provider:
      host: "{{ inventory_hostname_short }}"
      username: admin
      password: admin
  connection: local
'''

RETURN = ''' # '''

from ansible.module_utils.basic import AnsibleModule
from ..module_utils.api import WapiModule
from ..module_utils.api import normalize_ib_spec
from ..module_utils.api import NIOS_EXTENSIBLE_ATTRIBUTE


def main():
    ''' Main entry point for module execution
    '''

    ib_spec = dict(
        comment=dict(type='str'),
        default_value=dict(type='str'),
        list_values=dict(type='list', elements='str'),
        max=dict(type='int'),
        min=dict(type='int'),
        flags=dict(type='str'),
        name=dict(type='str', required=True, ib_req=True),
        type=dict(type='str', default='STRING',
                  choices=['DATE', 'EMAIL', 'ENUM', 'INTEGER', 'STRING', 'URL'])
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

    result = wapi.run(NIOS_EXTENSIBLE_ATTRIBUTE, ib_spec)

    module.exit_json(**result)


if __name__ == '__main__':
    main()
