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
module: content_library_item_info
short_description: Gather info about content library items.
description:
    - Gather info about content library items, using optional search parameters to refine output.
    - Content Library feature is introduced in vSphere 6.0 version.
    - This module does not work with vSphere version older than 67U2.
    - If neither O(library_item_id) nor O(library_item_name) are provided, all items in the relevant libraries will be returned.
author:
    - Ansible Cloud Team (@ansible-collections)
requirements:
    - vSphere Automation SDK
options:
    library_id:
        description:
            - The ID of the library to search within.
            - Mutually exclusive with O(library_name)
            - If neither O(library_id) nor O(library_name) are provided, all libraries will be considered relevant when searching.
        type: str
        required: false
    library_name:
        description:
            - The name of the library to search within.
            - Mutually exclusive with O(library_id)
            - If neither O(library_id) nor O(library_name) are provided, all libraries will be considered relevant when searching.
        type: str
        required: false
    library_item_id:
        description:
            - The ID of the library item for which to search.
            - Mutually exclusive with O(library_item_name).
            - Also mutually exclusive with O(library_id), and O(library_name) since item IDs are unique within a vCenter.
            - If O(library_id) or O(library_name) are defined, only items in that library will be included in the results.
            - If neither O(library_item_id) nor O(library_item_name) are provided, all items in the relevant libraries will be returned.
        type: str
        required: false
    library_item_name:
        description:
            - The ID of the library item for which to search.
            - Mutually exclusive with O(library_item_id).
            - If O(library_id) or O(library_name) are defined, only items in that library will be included in the results.
            - If neither O(library_item_id) nor O(library_item_name) are provided, all items in the relevant libraries will be returned.
        type: str
        required: false

extends_documentation_fragment:
    - vmware.vmware.base_options
    - vmware.vmware.additional_rest_options
'''

EXAMPLES = r'''
- name: Gather Info About All Library Items
  vmware.vmware.content_library_item_info: {}

- name: Gather Info About All Library Items In A Specific Library
  vmware.vmware.content_library_item_info:
    library_name: My Content Library

- name: Gather Info About A Specific Library Item
  vmware.vmware.content_library_item_info:
    library_item_id: c453d380-d864-4437-8e9f-b36395e4e629

# The returned info can be manipulated to extract attributes about the items
# For example:
- name: Gather Info About All Items
  vmware.vmware.content_library_item_info: {}
  register: _lib_items

- name: Get ISO File Names
  ansible.builtin.set_fact:
    my_iso_files: >-
      {{
        _lib_items.library_item_info |
        selectattr('type', 'equalto', 'iso') |
        map(attribute='name')
      }}

# You can attach an ISO file to a guest VM
- name: "Get info about item file storage"
  register: kickstart_item_info
  vmware.vmware.content_library_item_info:
    library_item_name: "os-installer.iso"

- name: Attach an installer ISO image to a guest VM
  vars:
    kickstart_iso_uri: >-
      {{
        kickstart_item_info['library_item_info'][0]['storage'][0]['storage_uris'][0] |
        ansible.builtin.regex_search('^(.*)\?','\1') | first
      }}
  vmware.vmware_rest.vcenter_vm_hardware_cdrom:
    vm: "{{ created_vm.id }}"
    type: IDE
    start_connected: true
    backing:
      iso_file: "{{ kickstart_iso_uri }}"
      type: ISO_FILE
'''

RETURN = r'''
library_item_info:
  description: A list of dictionaries describing the library items found
  returned: on success
  type: list
  sample: [
        {
            "cached": true,
            "certificate_verification_info": {
                "status": "NOT_AVAILABLE"
            },
            "content_version": "2",
            "creation_time": "2024-04-04T06:48:07.026Z",
            "description": "",
            "id": "fa4d4b87-db09-4b8e-903c-4f30a84e13fb",
            "last_modified_time": "2024-04-04T06:58:17.182Z",
            "library_id": "5a74aeab-3333-2222-1111-000000000",
            "metadata_version": "1",
            "name": "Fedora-Workstation-Live-ppc64le-39-1.5",
            "security_compliance": true,
            "size": 2082617344,
            "type": "iso",
            "version": "1",
            "storage": [
                {
                    "cached": true,
                    "checksum_info": {
                        "algorithm": "SHA1",
                        "checksum": ""
                    },
                    "name": "Fedora-Workstation-Live-ppc64le-39-1.5.iso",
                    "size": 2082617344,
                    "storage_backing": {
                        "datastore_id": "datastore-1111",
                        "type": "DATASTORE"
                    },
                    "storage_uris": [
                        "ds:///vmfs/volumes/11223344-11223344//contentlib-5a74aeab-333-222-1111-000000000/fa4d4b87-db09-4b8e-903c-4f30a84e13fb/Fedora-Workstation-Live-ppc64le-39-1.5.iso_11223344-1111-2222-3333-444444444444.iso?serverId=11111111-aaaa-bbbb-cccc-dddddddddddd"
                    ],
                    "version": "1"
                }
            ],
        },
        {
            "cached": true,
            "certificate_verification_info": {
                "status": "NOT_AVAILABLE"
            },
            "content_version": "2",
            "creation_time": "2024-08-27T05:49:38.112Z",
            "description": "",
            "id": "cb0fa396-2965-4e1e-bb2a-48bb8181b296",
            "last_modified_time": "2024-08-27T06:19:55.288Z",
            "library_id": "0d4ac97a-3333-2222-1111-000000000",
            "metadata_version": "1",
            "name": "CentOS-8.3.2011-x86_64-dvd1",
            "security_compliance": true,
            "size": 9264168960,
            "type": "iso",
            "version": "1",
            "storage": [
                {
                    "cached": true,
                    "checksum_info": {
                        "algorithm": "SHA1",
                        "checksum": ""
                    },
                    "name": "CentOS-8.3.2011-x86_64-dvd1.iso",
                    "size": 9264168960,
                    "storage_backing": {
                        "datastore_id": "datastore-1111",
                        "type": "DATASTORE"
                    },
                    "storage_uris": [
                        "ds:///vmfs/volumes/11223344-11223344//contentlib-5a74aeab-333-222-1111-000000000/fa4d4b87-db09-4b8e-903c-4f30a84e13fb/Fedora-Workstation-Live-ppc64le-39-1.5_11223344-1111-2222-3333-444444444444.iso?serverId=11111111-aaaa-bbbb-cccc-dddddddddddd"
                    ],
                    "version": "1"
                }
            ],

        },
        {
            "cached": true,
            "certificate_verification_info": {
                "status": "INTERNAL"
            },
            "content_version": "2",
            "creation_time": "2024-08-27T07:45:31.191Z",
            "description": "Windows Server 2022",
            "id": "7130053e-2463-49c6-84af-2db9f8af1eba",
            "last_modified_time": "2024-08-27T07:53:02.856Z",
            "library_id": "2c29da9f-3333-2222-1111-000000000",
            "metadata_version": "1",
            "name": "windows_server_2022",
            "security_compliance": true,
            "size": 15945369630,
            "type": "ovf",
            "version": "1"
        }
    ]
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.vmware.vmware.plugins.module_utils._module_rest_base import ModuleRestBase
from ansible_collections.vmware.vmware.plugins.module_utils.argument_spec import rest_compatible_argument_spec


class ContentLibaryItemInfo(ModuleRestBase):
    def __init__(self, module):
        super(ContentLibaryItemInfo, self).__init__(module)

    def __get_library_ids_to_search(self):
        """
        Return a list of library IDs to search for library items, based on
        search parameters.
        If a library ID was supplied, use that.
        If a library name was supplied, search using that name.
        Otherwise, search with a name of None, which essentially means any name

        Returns: list(str), list of IDs
        """
        if self.params['library_id']:
            return [self.params['library_id']]

        return self.get_content_library_ids(name=self.params['library_name'])

    def __get_library_item_ids_by_search_param(self, library_id=None):
        """
        Return a list of library items that match the module search parameters.
        If a library item was supplied, use that.
        If a library ID and/or library item name was supplied, search using those params.
        Otherwise, return all library item IDs
        """
        if self.params['library_item_id']:
            return [self.params['library_item_id']]

        if self.params['library_item_name']:
            return self.get_library_item_ids(name=self.params['library_item_name'], library_id=library_id)

        return self.library_item_service.list(library_id=library_id)

    def get_relevant_library_item_ids_by_params(self):
        if ((self.params['library_item_id'] or self.params['library_item_name']) and
           (not self.params['library_id'] and not self.params['library_name'])):
            # User is searching for a library item in any library, we dont need to specify a
            # library ID and can save an API call or two
            library_ids = [None]
        else:
            # User specified the library search params or is trying to gather all items, we need
            # to lookup all of the library IDs first
            library_ids = self.__get_library_ids_to_search()

        library_item_ids = []
        for library_id in library_ids:
            library_item_ids += self.__get_library_item_ids_by_search_param(library_id=library_id)

        return library_item_ids

    def get_relevant_library_item_info(self, library_item_ids):
        all_library_items_info = []
        for library_item_id in library_item_ids:
            item_info = self.library_item_service.get(library_item_id).to_dict()
            item_info['storage'] = [item.to_dict() for item in self.api_client.content.library.item.Storage.list(library_item_id=library_item_id)]
            all_library_items_info.append(item_info)

        return all_library_items_info


def main():
    argument_spec = rest_compatible_argument_spec()
    argument_spec.update(
        library_id=dict(type='str', required=False),
        library_name=dict(type='str', required=False),
        library_item_id=dict(type='str', required=False),
        library_item_name=dict(type='str', required=False),
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        mutually_exclusive=[
            ('library_id', 'library_name'),
            ('library_item_id', 'library_item_name'),
            ('library_item_id', 'library_id'),
            ('library_item_id', 'library_name')
        ],
    )

    library_item_info_module = ContentLibaryItemInfo(module)
    library_item_ids = library_item_info_module.get_relevant_library_item_ids_by_params()
    library_item_info = library_item_info_module.get_relevant_library_item_info(library_item_ids)
    module.exit_json(library_item_info=library_item_info)


if __name__ == '__main__':
    main()
