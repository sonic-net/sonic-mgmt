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
module: local_content_library
short_description: Manage a local content library.
description:
    - Create, update, or destroy a local content library.
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
            - The name of the local content library to manage.
        type: str
        required: true
        aliases: [library_name]
    description:
        description:
            - The description for the content library.
        type: str
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
            - The method of authentication to use if this is published local library.
            - The only options are NONE for no authentication or BASIC for username and password authentication.
            - The username for BASIC authentication cannot be changed and is vcsp.
        type: str
        default: NONE
        choices: ['BASIC', 'NONE']
    authentication_password:
        description:
            - The password to use when O(authentication_method) is V(BASIC).
            - If authentication is already enabled on the library, you must supply the password to update the library.
            - If O(authentication_current_password) is supplied, O(authentication_password) should be the new password you
              want to use for this library.
            - If BASIC auth is not enabled, this option is ignored.
        type: str
        required: false
    authentication_current_password:
        description:
            - The current password for the library when the library is using BASIC authentication.
            - If not supplied, the value of O(authentication_password) is used.
            - You must supply a password when the library is already configured with BASIC auth and O(state) is V(present).
            - If you want to update the password, set this to the old password and O(authentication_password) to the
              new password.
            - If BASIC auth is not enabled, this option is ignored.
        type: str
        required: false

    publish:
        description:
            - If true, this library will be published so other libraries can subscribe to it.
        type: bool
        default: False
    persist_json_enabled:
        description:
            - If true, a JSON file describing the library metadata will be kept in the library.
            - This file allows you to sync a remote library by copying the library contents instead
              of relying on HTTP.
        type: bool
        default: false
'''

EXAMPLES = r'''
- name: Create Local Content Library
  vmware.vmware.local_content_library:
    validate_certs: false
    hostname: "{{ vcenter_hostname }}"
    username: "{{ vcenter_username }}"
    password: "{{ vcenter_password }}"
    datastore_name: "{{ shared_storage }}"
    name: my-library
    state: present


- name: Publish Library Without Authentication
  vmware.vmware.local_content_library:
    validate_certs: false
    hostname: "{{ vcenter_hostname }}"
    username: "{{ vcenter_username }}"
    password: "{{ vcenter_password }}"
    datastore_name: "{{ shared_storage }}"
    name: my-library
    publish: true
    persist_json_enabled: true
    state: present

- name: Publish Library With Authentication
  vmware.vmware.local_content_library:
    validate_certs: false
    hostname: "{{ vcenter_hostname }}"
    username: "{{ vcenter_username }}"
    password: "{{ vcenter_password }}"
    datastore_name: "{{ shared_storage }}"
    name: my-library
    authentication_method: BASIC
    authentication_password: Mypassword!
    publish: true
    persist_json_enabled: true
    state: present

- name: Update Library Password
  vmware.vmware.local_content_library:
    validate_certs: false
    hostname: "{{ vcenter_hostname }}"
    username: "{{ vcenter_username }}"
    password: "{{ vcenter_password }}"
    datastore_name: "{{ shared_storage }}"
    name: my-library
    authentication_method: BASIC
    authentication_password: MyNewPassword1234!
    authentication_current_password: Mypassword!
    publish: true
    persist_json_enabled: true
    state: present

- name: Remove Library Password
  vmware.vmware.local_content_library:
    validate_certs: false
    hostname: "{{ vcenter_hostname }}"
    username: "{{ vcenter_username }}"
    password: "{{ vcenter_password }}"
    datastore_name: "{{ shared_storage }}"
    name: my-library
    authentication_password: MyNewPassword1234!
    publish: true
    persist_json_enabled: true
    state: present

- name: Unpublish Library Password
  vmware.vmware.local_content_library:
    validate_certs: false
    hostname: "{{ vcenter_hostname }}"
    username: "{{ vcenter_username }}"
    password: "{{ vcenter_password }}"
    datastore_name: "{{ shared_storage }}"
    name: my-library
    publish: false
    state: present


- name: Destroy Library
  vmware.vmware.local_content_library:
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
        - If the library was published, the publish_url is returned
    returned: On success
    type: dict
    sample: {
        "library": {
            "name": "domain-c111111",
            "id": "example-cluster",
            "publish_url": "https://vcenter.com:443/cls/vcsp/lib/111111-111111111-11111-111111/lib.json"
        },
    }
'''

import uuid
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.vmware.vmware.plugins.module_utils.argument_spec import rest_compatible_argument_spec
from ansible_collections.vmware.vmware.plugins.module_utils._module_rest_base import ModuleRestBase
from ansible_collections.vmware.vmware.plugins.module_utils._module_pyvmomi_base import ModulePyvmomiBase

try:
    from com.vmware.content_client import LibraryModel
    from com.vmware.content.library_client import StorageBacking, PublishInfo
except ImportError:
    pass


class VmwareContentLibrary(ModuleRestBase):
    def __init__(self, module):
        super().__init__(module)
        self.type = 'LOCAL'
        self.typed_library_service = self.api_client.content.LocalLibrary

        self.existing_library = self.__lookup_existing_library()
        if self.params['state'] == 'present':
            self.pyvmomi = ModulePyvmomiBase(module)
            self.__check_current_password_required_but_missing()

    def __check_current_password_required_but_missing(self):
        """
            When a library already has auth configured, vSphere requires the current password be present to
            change any settings. This checks to make sure the user provided it in those circumstances.
        """
        if not self.existing_library:
            return False

        _current_password_supplied = bool(self.params['authentication_current_password'])
        _basic_auth_enabled = (self.existing_library.publish_info.authentication_method == 'BASIC')
        if _basic_auth_enabled and not _current_password_supplied:
            self.module.fail_json(msg=(
                'The existing library currently has a password set. Managing this library requires that the current password '
                'is supplied in the authentication_current_password parameter'
            ))

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

    def __set_publication_spec(self, create_spec):
        """
            If the user selected to publish the library, add the publish_info details to the library spec
        """
        publish_spec = PublishInfo()
        publish_spec.published = self.params['publish']
        publish_spec.persist_json_enabled = self.params['persist_json_enabled']

        publish_spec.authentication_method = getattr(PublishInfo.AuthenticationMethod, self.params['authentication_method'])
        if self.params['authentication_method'] == 'BASIC':
            publish_spec.password = self.params['authentication_password']
        if self.params['authentication_current_password']:
            publish_spec.current_password = self.params['authentication_current_password']

        create_spec.publish_info = publish_spec

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
        self.__set_publication_spec(create_spec)

        return create_spec

    def create_library(self):
        datastore = self.pyvmomi.get_datastore_by_name_or_moid(self.params['datastore'], fail_on_missing=True)
        create_spec = self.create_library_spec(datastore_id=datastore._GetMoId())
        return self.typed_library_service.create(
            create_spec=create_spec,
            client_token=str(uuid.uuid4())
        )

    def library_needs_updating(self):
        """
            Check if the library has any settings that are different than what the user requested. If it does,
            return True
        """
        if self.params['authentication_current_password'] != self.params['authentication_password']:
            return True

        if self.existing_library.description != self.params['description']:
            return True

        if self.existing_library.publish_info.published != self.params['publish']:
            return True

        if self.params['publish']:
            if any([
                (self.existing_library.publish_info.persist_json_enabled != self.params['persist_json_enabled']),
                (self.existing_library.publish_info.authentication_method != self.params['authentication_method']),
            ]):
                return True

        return False

    def update_library(self):
        create_spec = self.create_library_spec()
        self.typed_library_service.update(
            self.existing_library.id,
            create_spec
        )

    def format_library_for_output(self, library_id=None, library=None):
        """
            This is a helper function to enrich the module output from library attributes.
            We need to add the publish URL to the output epending on if the library has been published or not.
        """
        if not library_id and not library:
            self.module.fail_json(msg='You need to supply either the library object or ID to format them for output')

        out = dict.fromkeys(['id', 'publish_url'], None)
        if library_id:
            library = self.library_service.get(library_id)
        out['id'] = library.id
        if self.params['publish']:
            out['publish_url'] = library.publish_info.publish_url
        return out

    def state_present(self, result):
        if not self.existing_library:
            result['changed'] = True
            if not self.module.check_mode:
                new_library_id = self.create_library()
                result['library'].update(self.format_library_for_output(library_id=new_library_id))

        else:
            if self.library_needs_updating():
                result['changed'] = True
                if not self.module.check_mode:
                    self.update_library()
                    result['library'].update(self.format_library_for_output(library_id=self.existing_library.id))
            else:
                result['library'].update(self.format_library_for_output(library=self.existing_library))


def main():
    argument_spec = rest_compatible_argument_spec()
    argument_spec.update(
        name=dict(type='str', required=True, aliases=['library_name']),
        description=dict(type='str', default='', aliases=['library_description']),
        datastore=dict(type='str', required=False, aliases=['datastore_name']),
        state=dict(type='str', default='present', choices=['present', 'absent']),

        authentication_method=dict(type='str', default='NONE', choices=['NONE', 'BASIC']),
        authentication_password=dict(type='str', required=False, no_log=True),
        authentication_current_password=dict(type='str', required=False, no_log=True),

        publish=dict(type='bool', default=False),
        persist_json_enabled=dict(type='bool', default=False)
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ('state', 'present', ('datastore',), False),
            ('authentication_method', 'BASIC', ('authentication_password',), False)
        ]
    )

    if not module.params['authentication_current_password']:
        module.params['authentication_current_password'] = module.params['authentication_password']

    vmware_library = VmwareContentLibrary(module)
    result = {'changed': False, 'library': {'name': module.params['name']}}

    if module.params['state'] == 'present':
        vmware_library.state_present(result)

    elif module.params['state'] == 'absent':
        if vmware_library.existing_library:
            result['changed'] = True
            if not module.check_mode:
                vmware_library.typed_library_service.delete(
                    library_id=vmware_library.existing_library.id
                )

    module.exit_json(**result)


if __name__ == '__main__':
    main()
