#!/usr/bin/python
# Copyright (c) 2018-2019 Red Hat, Inc.
# Copyright (c) 2020 Infoblox, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: nios_dtc_monitor_http
author: "Joachim Buyse (@jbisabel)"
version_added: "1.6.0"
short_description: Configure Infoblox NIOS DTC HTTP monitors
description:
  - Adds and/or removes instances of DTC HTTP monitor objects from Infoblox NIOS
    servers. This module manages C(dtc:monitor:http) objects using the Infoblox
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
      - Configures the port value for HTTP requests.
    type: int
    default: 80
  ciphers:
    description:
      - Configures an optional cipher list for the secure HTTP/S connection.
    type: str
  client_cert:
    description:
      - Configures an optional client certificate, supplied in a secure HTTP/S
        mode if present.
    type: str
  content_check:
    description:
      - Configures the content check type
    type: str
    choices:
      - EXTRACT
      - MATCH
      - NONE
    default: NONE
  content_check_input:
    description:
      - Configures the portion of the response to use as input for content check.
    type: str
    choices:
      - ALL
      - BODY
      - HEADERS
    default: ALL
  content_check_op:
    description:
      - Configures the content check success criteria operator.
    type: str
    choices:
      - EQ
      - GEQ
      - LEQ
      - NEQ
  content_check_regex:
    description:
      - Configures the content check regular expression. Values with leading
        or trailing white space are not valid for this field.
    type: str
  content_extract_group:
    description:
      - Configures the content extraction sub-expression to extract.
    type: int
    default: 0
  content_extract_type:
    description:
      - Configures the content extraction expected type for the extracted data.
    type: str
    choices:
      - INTEGER
      - STRING
    default: STRING
  content_extract_value:
    description:
      - Configures the content extraction value to compare with the extracted
        result. Values with leading or trailing white space are not valid for
        this field.
    type: str
  request:
    description:
      - Configures the HTTP request to send
    type: str
    default: GET /
  result:
    description:
      - Configures the type of the expected result
    type: str
    choices:
      - ANY
      - CODE_IS
      - CODE_IS_NOT
    default: ANY
  result_code:
    description:
      - Configures the expected return code
    type: int
    default: 200
  enable_sni:
    description:
      - Configures whether or not Server Name Indication (SNI) for the HTTPS
        monitor is enabled.
    type: bool
    default: false
  secure:
    description:
      - Configures the security status of the connection.
    type: bool
    default: false
  validate_cert:
    description:
      - Configures whether the validation of the remote server's certificate is
        enabled.
    type: bool
    default: true
  interval:
    description:
      - Configures the interval for HTTP health check.
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
      - Configures the timeout for HTTP health check in seconds.
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
- name: Configure a DTC HTTPS monitor
  infoblox.nios_modules.nios_dtc_monitor_http:
    name: https_monitor
    port: 443
    secure: true
    state: present
    provider:
      host: "{{ inventory_hostname_short }}"
      username: admin
      password: admin
  connection: local

- name: Add a comment to an existing DTC HTTPS monitor
  infoblox.nios_modules.nios_dtc_monitor_http:
    name: https_monitor
    comment: this is a test comment
    state: present
    provider:
      host: "{{ inventory_hostname_short }}"
      username: admin
      password: admin
  connection: local

- name: Remove a DTC HTTPS monitor from the system
  infoblox.nios_modules.nios_dtc_monitor_http:
    name: https_monitor
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
from ..module_utils.api import NIOS_DTC_MONITOR_HTTP
from ..module_utils.api import normalize_ib_spec


def main():
    ''' Main entry point for module execution
    '''

    ib_spec = dict(
        name=dict(required=True, ib_req=True),

        port=dict(type='int', default=80),
        ciphers=dict(type='str'),
        client_cert=dict(type='str'),
        content_check=dict(default='NONE', choices=['EXTRACT', 'MATCH', 'NONE']),
        content_check_input=dict(default='ALL', choices=['ALL', 'BODY', 'HEADERS']),
        content_check_op=dict(choices=['EQ', 'GEQ', 'LEQ', 'NEQ']),
        content_check_regex=dict(type='str'),
        content_extract_group=dict(type='int', default=0),
        content_extract_type=dict(default='STRING', choices=['INTEGER', 'STRING']),
        content_extract_value=dict(type='str'),
        request=dict(type='str', default='GET /'),
        result=dict(default='ANY', choices=['ANY', 'CODE_IS', 'CODE_IS_NOT']),
        result_code=dict(type='int', default=200),
        enable_sni=dict(type='bool', default=False),
        secure=dict(type='bool', default=False),
        validate_cert=dict(type='bool', default=True),
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
    result = wapi.run(NIOS_DTC_MONITOR_HTTP, ib_spec)

    module.exit_json(**result)


if __name__ == '__main__':
    main()
