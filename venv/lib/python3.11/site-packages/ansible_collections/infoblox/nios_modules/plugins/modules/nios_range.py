#!/usr/bin/python
# Copyright (c) 2018-2019 Red Hat, Inc.
# Copyright (c) 2020 Infoblox, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: nios_range
author: "Matthew Dennett (@matthewdennett)"
short_description: Configure Infoblox NIOS network range object
version_added: "1.5.0"
description:
  - Adds and/or removes instances of range objects from
    Infoblox NIOS servers.  This module manages NIOS DHCP range objects
    using the Infoblox WAPI interface over REST.
  - Supports both IPV4 and IPV6 internet protocols.
requirements:
  - infoblox-client
extends_documentation_fragment: infoblox.nios_modules.nios
notes:
    - This module supports C(check_mode).
options:
  network:
    description:
      - Specifies the network to add or remove DHCP range to.  The value
        should use CIDR notation.
    type: str
    required: true
    aliases:
      - cidr
  network_view:
    description:
      - Configures the name of the network view to associate with this
        configured instance.
    type: str
    default: default
  options:
    description:
      - Configures the set of DHCP options to be included as part of
        the configured network instance.  This argument accepts a list
        of values (see suboptions).  When configuring suboptions at
        least one of C(name) or C(num) must be specified.
    type: list
    default: []
    elements: dict
    suboptions:
      name:
        description:
          - The name of the DHCP option to configure. The standard options are
            C(router), C(router-templates), C(domain-name-servers), C(domain-name),
            C(broadcast-address), C(broadcast-address-offset), C(dhcp-lease-time),
            and C(dhcp6.name-servers).
        type: str
      num:
        description:
          - The number of the DHCP option to configure
        type: int
      value:
        description:
          - The value of the DHCP option specified by C(name)
        type: str
        required: true
      use_option:
        description:
          - Only applies to a subset of options (see NIOS API documentation)
        type: bool
        default: 'yes'
      vendor_class:
        description:
          - The name of the space this DHCP option is associated to
        type: str
        default: DHCP
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
  start_addr:
    description:
      - Configures IP address this object instance is to begin from. If
        'new_start_addr' is defined during a create operation this value is
        overridden with the value of 'new_start_addr'
    type: str
    required: true
    aliases:
      - start
      - first_addr
      - first
  new_start_addr:
    description:
      - Configures IP address to update this object instance to begin from.
    type: str
    required: false
    aliases:
      - new_start
      - new_first_addr
      - new_first
  end_addr:
    description:
      - Configures IP address this object instance is to end at. If
        'new_end_addr' is defined during a create operation this value is
        overridden with the value of 'new_end_addr'
    type: str
    required: true
    aliases:
      - end
      - last_addr
      - last
  new_end_addr:
    description:
      - Configures IP address to update this object instance to end at.
    type: str
    required: false
    aliases:
      - new_end
      - new_last_addr
      - new_last
  member:
    description:
      - The hostname of the Nios member which will be configured to server
        this object instance. Can not be configured when 'ms_server' or
        'failover_association' are configured.
    type: str
    required: false
  failover_association:
    description:
      - The name of the DHCP failover association which will be configured
        to server this object instance. A failover of MS or Nios members
        can be configured. Can not be configured when 'ms_server' or
        'member' are configured.
    type: str
    required: false
  ms_server:
    description:
      - The hostname of the MS member which will be configured to server
        this object instance. Can not be configured when 'member' or
        'failover_association' are configured.
    type: str
    required: false
  server_association_type:
    description:
      - Configured the type of server association that will be assigned to
        serve this object instance. This value is not required and will be
        set as needed automatically during module execution.
    type: str
    required: false
    choices:
      - NONE
      - FAILOVER
      - MEMBER
      - FAILOVER_MS
      - MS_SERVER
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
  disable:
    description:
      - Determines whether a range is disabled or not. When this is set
        to False, the range is enabled.
    type: bool
    default: false
  name:
    description:
      - Congifured the name of the Microsoft scope for the instance of the
        object on the NIOS server.
    type: str
'''

EXAMPLES = '''

- name: Configure a ipv4 reserved range
  infoblox.nios_modules.nios_range:
    network: 192.168.10.0/24
    start: 192.168.10.10
    end: 192.168.10.20
    name: Test Range 1
    comment: this is a test comment
    state: present
    provider:
      host: "{{ inventory_hostname_short }}"
      username: admin
      password: admin
  connection: local

- name: Upadtes a ipv4 reserved range
  infoblox.nios_modules.nios_range:
    network: 192.168.10.0/24
    start: 192.168.10.10
    new_start: 192.168.10.5
    end: 192.168.10.20
    new_end: 192.168.10.50
    name: Test Range 1
    comment: this is a test comment
    state: present
    provider:
      host: "{{ inventory_hostname_short }}"
      username: admin
      password: admin
  connection: local

- name: Configure a ipv4 range served by a member
  infoblox.nios_modules.nios_range:
    network: 192.168.10.0/24
    start: 192.168.10.10
    end: 192.168.10.20
    name: Test Range 1
    member: infoblox1.localdomain
    comment: this is a test comment
    state: present
    provider:
      host: "{{ inventory_hostname_short }}"
      username: admin
      password: admin
  connection: local

- name: Configure a ipv4 range served by a failover association
  infoblox.nios_modules.nios_range:
    network: 192.168.10.0/24
    start: 192.168.10.10
    end: 192.168.10.20
    name: Test Range 1
    failover_association: fo_association_01
    comment: this is a test comment
    state: present
    provider:
      host: "{{ inventory_hostname_short }}"
      username: admin
      password: admin
  connection: local

- name: Configure a ipv4 range with options
  infoblox.nios_modules.nios_range:
    network: 18.10.0.0/24
    network_view: custom
    start_addr: 18.10.0.12
    end_addr: 18.10.0.14
    options:
      - name: domain-name
        value: zone1.com
    comment: Created with Ansible
    state: present
    provider:
      host: "{{ inventory_hostname_short }}"
      username: admin
      password: admin
  connection: local

- name: Configure a ipv4 range served by a MS Server
  infoblox.nios_modules.nios_range:
    network: 192.168.10.0/24
    start: 192.168.10.10
    end: 192.168.10.20
    name: Test Range 1
    ms_server: dc01.ad.localdomain
    comment: this is a test comment
    state: present
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
from ..module_utils.api import NIOS_RANGE
from ..module_utils.api import normalize_ib_spec


def options(module):
    ''' Transforms the module argument into a valid WAPI struct
    This function will transform the options argument into a structure that
    is a valid WAPI structure in the format of:
        {
            name: <value>,
            num: <value>,
            value: <value>,
            use_option: <value>,
            vendor_class: <value>
        }
    It will remove any options that are set to None since WAPI will error on
    that condition.  It will also verify that either `name` or `num` is
    set in the structure but does not validate the values are equal.
    The remainder of the value validation is performed by WAPI
    '''
    options = list()
    for item in module.params['options']:
        opt = dict([(k, v) for k, v in iteritems(item) if v is not None])
        if 'name' not in opt and 'num' not in opt:
            module.fail_json(msg='one of `name` or `num` is required for option value')
        options.append(opt)
    return options


def check_vendor_specific_dhcp_option(module, ib_spec):
    '''This function will check if the argument dhcp option belongs to vendor-specific and if yes then will remove
     use_options flag which is not supported with vendor-specific dhcp options.
    '''
    for key, value in iteritems(ib_spec):
        if isinstance(module.params[key], list):
            for temp_dict in module.params[key]:
                if 'num' in temp_dict:
                    if temp_dict['num'] in (43, 124, 125, 67, 60):
                        del temp_dict['use_option']
    return ib_spec


def convert_range_member_to_struct(module):
    '''This function will check the module input to ensure that only one member assignment type is specified at once.
    Member passed in is converted to the correct struct for the API to understand bassed on the member type.
    '''
    # Error checking that only one member type was defined
    params = [k for k in module.params.keys() if module.params[k] is not None]
    opts = list(set(params).intersection(['member', 'failover_association', 'ms_server']))
    if len(opts) > 1:
        raise AttributeError("'%s' can not be defined when '%s' is defined!" % (opts[0], opts[1]))

    # A member node was passed in. Ehsure the correct type and struct
    if 'member' in opts:
        module.params['member'] = {'_struct': 'dhcpmember', 'name': module.params['member']}
        module.params['server_association_type'] = 'MEMBER'
    # A FO association was passed in. Ensure the correct type is set
    elif 'failover_association' in opts:
        module.params['server_association_type'] = 'FAILOVER'
    # MS server was passed in. Ensure the correct type and struct
    elif 'ms_server' in opts:
        module.params['ms_server'] = {'_struct': 'msdhcpserver', 'ipv4addr': module.params['ms_server']}
        module.params['server_association_type'] = 'MS_SERVER'
    else:
        module.params['server_association_type'] = 'NONE'
    return module


def main():
    ''' Main entry point for module execution
    '''
    option_spec = dict(
        # one of name or num is required; enforced by the function options()
        name=dict(),
        num=dict(type='int'),

        value=dict(required=True),

        use_option=dict(type='bool', default=True),
        vendor_class=dict(default='DHCP')
    )

    # This is what gets posted to the WAPI API
    ib_spec = dict(
        network=dict(required=True, aliases=['cidr']),
        network_view=dict(default='default', ib_req=True),
        start_addr=dict(required=True, aliases=['start', 'first_addr', 'first'], type='str', ib_req=True),
        new_start_addr=dict(aliases=['new_start', 'new_first_addr', 'new_first'], type='str'),
        end_addr=dict(required=True, aliases=['end', 'last_addr', 'last'], type='str', ib_req=True),
        new_end_addr=dict(aliases=['new_end', 'new_last_addr', 'new_last'], type='str'),
        name=dict(type='str'),
        disable=dict(type='bool', default='false',),
        options=dict(type='list', elements='dict', options=option_spec, transform=options, default=[]),
        member=dict(type='str'),
        failover_association=dict(type='str'),
        ms_server=dict(type='str'),
        server_association_type=dict(type='str', choices=['NONE', 'FAILOVER', 'MEMBER', 'FAILOVER_MS', 'MS_SERVER']),
        extattrs=dict(type='dict'),
        comment=dict()
    )

    argument_spec = dict(
        provider=dict(required=True),
        state=dict(default='present', choices=['present', 'absent'])
    )

    argument_spec.update(normalize_ib_spec(ib_spec))
    argument_spec.update(WapiModule.provider_spec)

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    module = convert_range_member_to_struct(module)
    wapi = WapiModule(module)
    # to check for vendor specific dhcp option
    ib_spec = check_vendor_specific_dhcp_option(module, ib_spec)

    result = wapi.run(NIOS_RANGE, ib_spec)

    module.exit_json(**result)


if __name__ == '__main__':
    main()
