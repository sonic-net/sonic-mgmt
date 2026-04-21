#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
module: na_ontap_cifs_unix_symlink_mapping
short_description: NetApp ONTAP module to manage UNIX symbolic link mapping for CIFS clients.
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap_rest
version_added: '22.9.0'
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
  - Create/ modify/ delete a UNIX symbolic link mapping for a CIFS client.
options:
  state:
    description:
      - Whether the specified symlink mapping should exist or not.
    choices: ['present', 'absent']
    type: str
    default: present

  vserver:
    description:
      - Name of the vserver to use.
    type: str
    required: true

  unix_path:
    description:
      - Specifies the UNIX path prefix to be matched for the mapping.
      - It must begin and end with a forward slash (/).
    type: str
    required: true

  share_name:
    description:
      - Specifies the CIFS share name on the destination CIFS server to which the UNIX symbolic link is pointing.
    type: str

  cifs_server:
    description:
      - Specifies the destination CIFS server (DNS name, IP address, or NetBIOS name).
      - This field is mandatory if the locality of the symbolic link is 'widelink'.
    type: str

  cifs_path:
    description:
      - Specifies the CIFS path on the destination to which the symbolic link maps.
      - Note that this value is specified by using a UNIX-style path. It must begin and end with a forward slash (/).
    type: str

  locality:
    description:
      - Specifies whether the CIFS symbolic link is a local link or wide link. The default setting is local.
      - The following values are supported
        local - Local symbolic link maps only to the same CIFS share.
        widelink - Wide symbolic link maps to any CIFS share on the network.
    type: str
    choices: ['local', 'widelink']
    default: 'local'

  home_directory:
    description:
      - Specify if the destination share is a home directory. The default value is false.
    type: bool
    default: False

notes:
  - Only supported with REST and requires ONTAP 9.6 or later.

"""

EXAMPLES = """
- name: Create a UNIX symlink mapping for CIFS share
  netapp.ontap.na_ontap_cifs_unix_symlink_mapping:
    state: present
    vserver: "{{ svm }}"
    unix_path: "/example1/"
    share_name: "share1"
    cifs_path: "/path1/test_dir/"
    cifs_server: "CIFS"
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: "{{ validate_certs }}"

- name: Update a specific UNIX symlink mapping for a SVM
  netapp.ontap.na_ontap_cifs_unix_symlink_mapping:
    state: present
    vserver: "{{ svm }}"
    unix_path: "/example1/"
    share_name: "share2"
    cifs_path: "/path2/test_dir/"
    cifs_server: "CIFS"
    locality: "widelink"
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: "{{ validate_certs }}"

- name: Remove a specific UNIX symlink mapping for a SVM
  netapp.ontap.na_ontap_cifs_unix_symlink_mapping:
    state: absent
    vserver: "{{ svm }}"
    unix_path: "/example1/"
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: "{{ validate_certs }}"
"""

RETURN = """
"""

import traceback
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic


class NetAppOntapCifsUnixSymlink:
    def __init__(self):
        self.argument_spec = netapp_utils.na_ontap_rest_only_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            vserver=dict(required=True, type='str'),
            unix_path=dict(required=True, type='str'),
            share_name=dict(required=False, type='str'),
            cifs_path=dict(required=False, type='str'),
            cifs_server=dict(required=False, type='str'),
            locality=dict(required=False, type='str', choices=['local', 'widelink'], default='local'),
            home_directory=dict(required=False, type='bool', default=False)
        ))
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            required_if=[
                ('state', 'present', ['share_name', 'cifs_path']),
                ('locality', 'widelink', ['cifs_server']),
            ],
            supports_check_mode=True
        )
        self.svm_uuid = None
        self.na_helper = NetAppModule(self.module)
        self.parameters = self.na_helper.check_and_set_parameters(self.module)
        self.rest_api = netapp_utils.OntapRestAPI(self.module)
        self.rest_api.fail_if_not_rest_minimum_version('na_ontap_cifs_unix_symlink_mapping:', 9, 6)

    @staticmethod
    def validate_path(path):
        if not path.startswith('/'):
            path = "/%s" % path
        if not path.endswith('/'):
            path = "%s/" % path
        return path

    @staticmethod
    def encode_path(path):
        return path.replace('/', '%2F')

    def get_symlink_mapping_rest(self):
        """
        Retrieves a specific UNIX symbolink mapping for a SVM
        """
        api = 'protocols/cifs/unix-symlink-mapping'
        query = {'svm.name': self.parameters.get('vserver'),
                 'unix_path': self.parameters['unix_path'],
                 'fields': 'svm.uuid,'
                           'unix_path,'
                           'target.share,'
                           'target.path,'}
        if self.parameters.get('cifs_server') is not None:
            query['fields'] += 'target.server,'
        if self.parameters.get('locality') is not None:
            query['fields'] += 'target.locality,'
        if self.parameters.get('home_directory') is not None:
            query['fields'] += 'target.home_directory,'

        record, error = rest_generic.get_one_record(self.rest_api, api, query)
        if error:
            self.module.fail_json(msg='Error while fetching cifs unix symlink mapping: %s' % to_native(error),
                                  exception=traceback.format_exc())
        if record:
            self.svm_uuid = self.na_helper.safe_get(record, ['svm', 'uuid'])
            return self.format_record(record)
        return None

    def format_record(self, record):
        return {
            'unix_path': record.get('unix_path'),
            'share_name': self.na_helper.safe_get(record, ['target', 'share']),
            'cifs_path': self.na_helper.safe_get(record, ['target', 'path']),
            'cifs_server': self.na_helper.safe_get(record, ['target', 'server']),
            'locality': self.na_helper.safe_get(record, ['target', 'locality']),
            'home_directory': self.na_helper.safe_get(record, ['target', 'home_directory'])
        }

    def create_symlink_mapping_rest(self):
        """
        Creates a UNIX symbolink mapping for CIFS share
        """
        api = 'protocols/cifs/unix-symlink-mapping'
        body = {
            'svm.name': self.parameters['vserver'],
            'unix_path': self.parameters['unix_path'],
            'target': {
                'share': self.parameters['share_name'],
                'path': self.parameters['cifs_path']
            }
        }
        if 'cifs_server' in self.parameters:
            body['target.server'] = self.parameters['cifs_server']
        if 'locality' in self.parameters:
            body['target.locality'] = self.parameters['locality']
        if 'home_directory' in self.parameters:
            body['target.home_directory'] = self.parameters['home_directory']

        dummy, error = rest_generic.post_async(self.rest_api, api, body)
        if error is not None:
            self.module.fail_json(msg='Error while creating cifs unix symlink mapping: %s' % to_native(error),
                                  exception=traceback.format_exc())

    def modify_symlink_mapping_rest(self, modify):
        """
        Updates a specific UNIX symbolink mapping for a SVM
        """
        api = 'protocols/cifs/unix-symlink-mapping/%s/%s' % (self.svm_uuid, self.encode_path(self.parameters['unix_path']))
        body = {'target': {}}
        for key, option in [
            ('share', 'share_name'),
            ('path', 'cifs_path'),
            ('server', 'cifs_server'),
            ('locality', 'locality'),
            ('home_directory', 'home_directory'),
        ]:
            if modify.get(option) is not None:
                body['target'][key] = modify[option]

        dummy, error = rest_generic.patch_async(self.rest_api, api, uuid_or_name=None, body=body)
        if error:
            self.module.fail_json(msg='Error while modifying cifs unix symlink mapping: %s.' % to_native(error),
                                  exception=traceback.format_exc())

    def delete_symlink_mapping_rest(self):
        """
        Removes a specific UNIX symbolink mapping for a SVM
        """
        api = 'protocols/cifs/unix-symlink-mapping/%s/%s' % (self.svm_uuid, self.encode_path(self.parameters['unix_path']))
        dummy, error = rest_generic.delete_async(self.rest_api, api, uuid=None)
        if error is not None:
            self.module.fail_json(msg='Error while deleting cifs unix symlink mapping: %s' % to_native(error))

    def apply(self):
        # validate leading and trailing forward slashes in unix_path & cifs_path
        for option in ['unix_path', 'cifs_path']:
            if self.parameters.get(option) is not None:
                self.parameters[option] = self.validate_path(self.parameters[option])

        current = self.get_symlink_mapping_rest()
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        modify = self.na_helper.get_modified_attributes(current, self.parameters)
        if self.na_helper.changed and not self.module.check_mode:
            if cd_action == 'create':
                self.create_symlink_mapping_rest()
            elif cd_action == 'delete':
                self.delete_symlink_mapping_rest()
            elif modify:
                self.modify_symlink_mapping_rest(modify)
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action, modify)
        self.module.exit_json(**result)


def main():
    symlink_mapping = NetAppOntapCifsUnixSymlink()
    symlink_mapping.apply()


if __name__ == '__main__':
    main()
