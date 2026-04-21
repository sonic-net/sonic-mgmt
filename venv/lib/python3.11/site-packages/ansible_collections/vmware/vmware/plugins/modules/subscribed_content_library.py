#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2019, Ansible Project
# Copyright: (c) 2019, Pavan Bidkar <pbidkar@vmware.com>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: subscribed_content_library
short_description: Manage a subscribed content library.
description:
    - Create, update, or destroy a subscribed content library.
author:
    - Ansible Cloud Team (@ansible-collections)
requirements:
    - vSphere Automation SDK

extends_documentation_fragment:
    - vmware.vmware.base_options
    - vmware.vmware.additional_rest_options

options:
    name:
        description:
            - The name of the subscribed content library to manage.
        type: str
        required: true
        aliases: [library_name]
    description:
        description:
            - The description for the content library.
        type: str
        required: false
        aliases: [library_description]
        default: ''
    datastore:
        description:
            - The name of the datastore that should be a storage backing for the library.
            - This parameter is required when O(state) is V(present)
            - This parameter only takes effect when the library is first created. You cannot change the
              storage backing for an existing library, and the module will not check this value in that case.
        type: str
        required: false
        aliases: [datastore_name]
    state:
        description:
            - Whether the content library should be present or absent.
        type: str
        default: present
        choices: [present, absent]

    authentication_method:
        description:
            - The method of authentication to use if this is a subscribed or published local library.
            - If the library is a local, non-published library, this option has no effect.
            - The only options are NONE for no authentication or BASIC for username and password authentication.
            - The username for BASIC auth cannot be changed, and is vcsp.
        type: str
        default: NONE
        choices: ['BASIC', 'NONE']
    authentication_password:
        description:
            - The password to use when O(authentication_method) is V(BASIC).
            - If BASIC auth is not enabled, this option is ignored.
        type: str
        required: false
    always_update_password:
        description:
            - If true and O(authentication_password) is set, this module will always report a change and
              set the password value to O(authentication_password) .
            - If false, other properties are still checked for differences. If a difference is found,
              the value of O(authentication_password) is still used.
            - If O(authentication_password) is unset, this parameter is ignored.
            - This option is needed because there is no way to check the current password value and
              compare it against the desired password value.
        default: true
        type: bool

    subscription_url:
        description:
            - The URL of the remote library to which you want to subscribe.
            - This parameter is required when configuring a subscribed library.
        type: str
        required: false
    ssl_thumbprint:
        description:
            - If specified, the thumbprint presented by the subscribed URL will be validated against this value.
        type: str
        required: false
    update_on_demand:
        description:
            - Whether to download all content on demand, or download all content ahead of time.
        type: bool
        default: false
'''

EXAMPLES = r'''
- name: Create a subscribed content library with no authentication
  vmware.vmware.subscribed_content_library:
    hostname: '{{ vcenter_hostname }}'
    username: '{{ vcenter_username }}'
    password: '{{ vcenter_password }}'
    name: my-library
    subscription_url: https://my-vcenter.com/whatever


- name: Create a library that uses a password for auth
  vmware.vmware.subscribed_content_library:
    hostname: '{{ vcenter_hostname }}'
    username: '{{ vcenter_username }}'
    password: '{{ vcenter_password }}'
    name: my-library
    subscription_url: https://my-vcenter.com/whatever
    authentication_method: BASIC
    authentication_password: AVeryGoodPassword?


- name: Destroy subscribed library
  vmware.vmware.subscribed_content_library:
    validate_certs: false
    hostname: "{{ vcenter_hostname }}"
    username: "{{ vcenter_username }}"
    password: "{{ vcenter_password }}"
    name: my-library
    state: absent
'''

RETURN = r'''
library:
    description:
        - Identifying information about the library
        - If the library was removed, only the name is returned
    returned: On success
    type: dict
    sample: {
        "library": {
            "name": "domain-c111111",
            "id": "example-cluster"
        },
    }
'''

import uuid
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.vmware.vmware.plugins.module_utils.argument_spec import rest_compatible_argument_spec
from ansible.module_utils.common.text.converters import to_native
from ansible_collections.vmware.vmware.plugins.module_utils._module_rest_base import ModuleRestBase
from ansible_collections.vmware.vmware.plugins.module_utils._module_pyvmomi_base import ModulePyvmomiBase

try:
    from com.vmware.content_client import LibraryModel
    from com.vmware.content.library_client import StorageBacking, SubscriptionInfo
    from com.vmware.vapi.std.errors_client import ResourceInaccessible
except ImportError:
    pass


class VmwareContentLibrary(ModuleRestBase):
    def __init__(self, module):
        """Constructor."""
        super().__init__(module)
        self.type = 'SUBSCRIBED'
        self.typed_library_service = self.api_client.content.SubscribedLibrary

        self.existing_library = self.__lookup_existing_library()
        if self.params['state'] == 'present':
            self.pyvmomi = ModulePyvmomiBase(module)

    def __lookup_existing_library(self):
        """
            Check if a library with the specified name and type exists. vSphere technically lets you name libraries the same thing,
            but that seems impractical so we don't support it.
        """
        library_ids = self.get_content_library_ids(name=self.params['name'], library_type=self.type)
        if len(library_ids) > 1:
            self.module.fail_json(msg='More than one library has the same name and type. Cannot determine which one to manage.')

        if not library_ids:
            return None

        return self.library_service.get(library_ids[0])

    def __set_subscription_spec(self, create_spec):
        subscription_spec = SubscriptionInfo()
        subscription_spec.on_demand = self.params['update_on_demand']
        subscription_spec.automatic_sync_enabled = True
        subscription_spec.subscription_url = self.params['subscription_url']
        subscription_spec.ssl_thumbprint = self.params['ssl_thumbprint']

        subscription_spec.authentication_method = getattr(SubscriptionInfo.AuthenticationMethod, self.params['authentication_method'])
        if self.params['authentication_method'] == 'BASIC':
            subscription_spec.user_name = 'vcsp'
            subscription_spec.password = self.params['authentication_password']

        create_spec.subscription_info = subscription_spec

    def create_library_spec(self, datastore_id: str = None):
        """
            Create a spec that describes a library, according the the vSphere REST API
        """
        create_spec = LibraryModel()
        create_spec.name = self.params['name']
        create_spec.description = self.params['description']
        create_spec.type = getattr(create_spec.LibraryType, self.type)
        if datastore_id:
            create_spec.storage_backings = [
                StorageBacking(type=StorageBacking.Type.DATASTORE, datastore_id=datastore_id)
            ]
        self.__set_subscription_spec(create_spec)

        return create_spec

    def create_library(self):
        datastore = self.pyvmomi.get_datastore_by_name_or_moid(self.params['datastore'], fail_on_missing=True)
        create_spec = self.create_library_spec(datastore_id=datastore._GetMoId())
        try:
            library_id = self.typed_library_service.create(
                create_spec=create_spec,
                client_token=str(uuid.uuid4())
            )
        except ResourceInaccessible as e:
            self.module.fail_json(msg=(
                "vCenter Failed to make connection to %s with exception: %s. If using HTTPS, check "
                "that the SSL thumbprint is valid" % (self.params['subscription_url'], to_native(e))
            ))

        return library_id

    def library_needs_updating(self):
        """
            Check if the library has any settings that are different than what the user requested. If it does,
            return True
        """
        if self.params['always_update_password'] and self.params['authentication_password']:
            return True

        if any([
            (self.existing_library.description != self.params['description']),
            (self.existing_library.subscription_info.authentication_method != self.params['authentication_method']),
            (self.existing_library.subscription_info.subscription_url != self.params['subscription_url']),
            (self.existing_library.subscription_info.on_demand != self.params['update_on_demand']),
            (self.existing_library.subscription_info.ssl_thumbprint != self.params['ssl_thumbprint'])
        ]):
            return True

    def update_library(self):
        create_spec = self.create_library_spec()
        try:
            self.typed_library_service.update(
                self.existing_library.id,
                create_spec
            )
        except ResourceInaccessible as e:
            self.module.fail_json(msg=(
                "vCenter Failed to make connection to %s with exception: %s. If using HTTPS, check "
                "that the SSL thumbprint is valid" % (self.params['subscription_url'], to_native(e))
            ))


def main():
    argument_spec = rest_compatible_argument_spec()
    argument_spec.update(
        name=dict(type='str', required=True, aliases=['library_name']),
        description=dict(type='str', default='', aliases=['library_description']),
        datastore=dict(type='str', required=False, aliases=['datastore_name']),
        state=dict(type='str', default='present', choices=['present', 'absent']),

        authentication_method=dict(type='str', default='NONE', choices=['NONE', 'BASIC']),
        authentication_password=dict(type='str', required=False, no_log=True),
        always_update_password=dict(type='bool', default=True),

        subscription_url=dict(type='str', required=False),
        ssl_thumbprint=dict(type='str', required=False),
        update_on_demand=dict(type='bool', default=False),
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ('state', 'present', ('datastore', 'subscription_url'), False),
            ('authentication_method', 'BASIC', ('authentication_password',), False)
        ]
    )

    vmware_library = VmwareContentLibrary(module)
    result = {'changed': False, 'library': {'name': module.params['name']}}

    if module.params['state'] == 'present':
        if not vmware_library.existing_library:
            result['changed'] = True
            if not vmware_library.module.check_mode:
                new_library_id = vmware_library.create_library()
                result['library']['id'] = new_library_id

        else:
            result['library']['id'] = vmware_library.existing_library.id
            if vmware_library.library_needs_updating():
                result['changed'] = True
                if not vmware_library.module.check_mode:
                    vmware_library.update_library()

    elif module.params['state'] == 'absent':
        if vmware_library.existing_library:
            result['changed'] = True
            if not vmware_library.module.check_mode:
                vmware_library.typed_library_service.delete(library_id=vmware_library.existing_library.id)

    module.exit_json(**result)


if __name__ == '__main__':
    main()
