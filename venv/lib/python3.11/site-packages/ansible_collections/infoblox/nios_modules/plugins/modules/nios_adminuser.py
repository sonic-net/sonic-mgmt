#!/usr/bin/python
# Copyright (c) 2018-2019 Red Hat, Inc.
# Copyright (c) 2020 Infoblox, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: nios_adminuser
author: "Nitish K S (@nitish-ks)"
short_description: Configure Infoblox NIOS Adminuser
version_added: "1.8.0"
description:
  - Adds and/or removes instances of adminuser objects from
    Infoblox NIOS servers. This module manages NIOS C(adminuser) objects
    using the Infoblox WAPI interface over REST.
requirements:
  - infoblox-client
extends_documentation_fragment: infoblox.nios_modules.nios
notes:
    - This module supports C(check_mode).
options:
  name:
    description:
      - Specifies the adminuser name to add or remove from the system.
        Users can also update the name as it is possible
        to pass a dict containing I(new_name), I(old_name). See examples.
    required: true
    type: str
  admin_groups:
    description:
      - The names of the Admin Groups to which this Admin User belongs.
        Currently, this is limited to only one Admin Group.
    required: true
    type: list
    elements: str
  password:
    description:
      - The password for the administrator to use when logging in.
    type: str
  auth_method:
    description:
      - Authentication method for the admin user.
    default: KEYPAIR
    choices:
      - KEYPAIR
      - KEYPAIR_PASSWORD
    type: str
  auth_type:
    description:
      - Authentication type for the admin user.
    default: LOCAL
    choices:
      - LOCAL
      - REMOTE
      - SAML
      - SAML_LOCAL
    type: str
  ca_certificate_issuer:
    description:
      - The CA certificate that is used for user lookup during authentication.
    type: str
  client_certificate_serial_number:
    description:
      - The serial number of the client certificate.
    type: str
  disable:
    description:
      - Determines whether the admin user is disabled or not. When this is set
        to False, the admin user is enabled.
    default: false
    type: bool
  email:
    description:
      - Email address of the admin user.
    type: str
  enable_certificate_authentication:
    description:
      - Determines whether the user is allowed to log in only with the
        certificate. Regular username/password authentication will be disabled
        for this user.
    default: false
    type: bool
  time_zone:
    description:
      - The time zone for this admin user.
    default: UTC
    type: str
  use_time_zone:
    description:
      - Use flag for I(time_zone).
    default: false
    type: bool
  ssh_keys:
    description:
      - List of SSH keys for the admin user.
    type: list
    default: []
    elements: dict
    suboptions:
      key_name:
        description:
          - Unique identifier for the key
        type: str
      key_type:
        description:
          - Type of the SSH key.
        choices:
          - ECDSA
          - ED25519
          - RSA
        type: str
      key_value:
        description:
          - SSH key text.
        type: str
  use_ssh_keys:
    description:
      - Enable/disable the ssh keypair authentication.
    default: false
    type: bool
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
- name: Create a new admin user
  infoblox.nios_modules.nios_adminuser:
    name: ansible_user
    admin_groups: admin-group
    password: "secure_password"
    state: present
    provider:
      host: "{{ inventory_hostname_short }}"
      username: admin
      password: admin
  connection: local

- name: Update admin user name
  infoblox.nios_modules.nios_adminuser:
    name: {new_name: new_user, old_name: ansible_user}
    admin_groups: admin-group
    state: present
    provider:
      host: "{{ inventory_hostname_short }}"
      username: admin
      password: admin
  connection: local

- name: Create admin user with remote authentication
  infoblox.nios_modules.nios_adminuser:
    name: remote_admin_user
    admin_groups: admin-group
    auth_type: "REMOTE"
    email: "admin@example.com"
    use_time_zone: true
    time_zone: 'US/Hawaii'
    extattrs:
      Site: "USA"
    state: present
    provider:
      host: "{{ inventory_hostname_short }}"
      username: admin
      password: admin
  connection: local

- name: Create admin user with ssh keys
  infoblox.nios_modules.nios_adminuser:
    name: cloud_user
    admin_groups: cloud-api-only
    comment: "Created by Ansible"
    disable : false
    password: "secure_password"
    use_ssh_keys: true
    ssh_keys:
      - key_name: "sshkey1"
        key_type: "RSA"
        key_value: "{{ lookup('file', '~/.ssh/id_rsa.pub') }}"
      - key_name: "sshkey2"
        key_type: "ECDSA"
        key_value: "{{ lookup('file', '~/.ssh/id_ecdsa.pub') }}"
    state: present
    provider:
      host: "{{ inventory_hostname_short }}"
      username: admin
      password: admin
  connection: local

- name: Update admin user to enable certificate authentication
  infoblox.nios_modules.nios_adminuser:
    name: admin_user
    admin_groups: admin-group
    enable_certificate_authentication: true
    ca_certificate_issuer: 'CN="ib-root-ca"'
    client_certificate_serial_number: "397F9435000100000031"
    state: present
    provider:
      host: "{{ inventory_hostname_short }}"
      username: admin
      password: admin
  connection: local

- name: Remove admin user
  infoblox.nios_modules.nios_adminuser:
    name: new_user
    admin_groups: admin-group
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
from ..module_utils.api import NIOS_ADMINUSER
from ..module_utils.api import normalize_ib_spec


def main():
    ''' Main entry point for module execution
    '''

    def cacert_transform(module):
        cacert_ref = str()
        if not module.params['client_certificate_serial_number']:
            module.fail_json(
                msg='Client certificate Serial Number is required.')

        cacert = wapi.get_object(
            'cacertificate',
            {
                'issuer': module.params['ca_certificate_issuer'],
                'serial': module.params['client_certificate_serial_number']
            })
        if cacert:
            cacert_ref = cacert[0]['_ref']
        else:
            module.fail_json(
                msg='CA Certificate \'%s\' could not be found. '
                'Provide a valid certificate Issuer and Serial Number.' %
                module.params['ca_certificate_issuer'])
        return cacert_ref

    ssh_key_spec = dict(
        key_name=dict(type='str'),
        key_type=dict(type='str', choices=['ECDSA', 'ED25519', 'RSA']),
        key_value=dict(type='str', no_log=True)
    )

    ib_spec = dict(
        name=dict(required=True, ib_req=True),
        admin_groups=dict(type='list', elements='str', required=True, ib_req=True),
        password=dict(no_log=True),
        auth_method=dict(default='KEYPAIR', choices=['KEYPAIR', 'KEYPAIR_PASSWORD']),
        auth_type=dict(default='LOCAL', choices=['LOCAL', 'REMOTE', 'SAML', 'SAML_LOCAL']),
        ca_certificate_issuer=dict(transform=cacert_transform),
        client_certificate_serial_number=dict(),
        disable=dict(type='bool', default=False),
        email=dict(),
        enable_certificate_authentication=dict(type='bool', default=False),
        time_zone=dict(default='UTC'),
        use_time_zone=dict(type='bool', default=False),
        ssh_keys=dict(type='list', default=[], no_log=False, elements='dict', options=ssh_key_spec),
        use_ssh_keys=dict(type='bool', default=False),
        extattrs=dict(type='dict'),
        comment=dict()
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
    result = wapi.run(NIOS_ADMINUSER, ib_spec)

    module.exit_json(**result)


if __name__ == '__main__':
    main()
