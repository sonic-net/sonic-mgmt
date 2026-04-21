#!/usr/bin/python

# (c) 2018-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
# import untangle

'''
na_ontap_cifs
'''

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
  - Create or destroy or modify(path) cifs-share on ONTAP.
extends_documentation_fragment:
  - netapp.ontap.netapp.na_ontap
module: na_ontap_cifs

options:

  comment:
    description:
      - The CIFS share description.
    type: str
    version_added: 21.7.0

  path:
    description:
      - The file system path that is shared through this CIFS share. The path is the full, user visible path relative
        to the vserver root, and it might be crossing junction mount points. The path is in UTF8 and uses forward
        slash as directory separator.
    type: str

  vserver:
    description:
      - Vserver containing the CIFS share.
    required: true
    type: str

  name:
    description:
      - The name of the CIFS share. The CIFS share name is a UTF-8 string with the following characters being
        illegal; control characters from 0x00 to 0x1F, both inclusive, 0x22 (double quotes)
    required: true
    aliases: ['share_name']
    type: str

  share_properties:
    description:
      - The list of properties for the CIFS share.
      - Not supported with REST.
      - share-properties are separate fields in the REST API.
      - You can achieve this functionality by setting C(access_based_enumeration), C(change_notify), C(encryption),
        C(home_directory), C(oplocks), C(show_snapshot), C(continuously_available) and C(namespace_caching).
    type: list
    elements: str
    version_added: 2.8.0

  symlink_properties:
    description:
      - The list of symlink properties for this CIFS share.
      - Not supported with REST, this option is replaced with C(unix_symlink) in REST.
    type: list
    elements: str
    version_added: 2.8.0

  state:
    choices: ['present', 'absent']
    description:
      - Whether the specified CIFS share should exist or not.
    type: str
    default: present

  vscan_fileop_profile:
    choices: ['no_scan', 'standard', 'strict', 'writes_only']
    description:
      - Profile_set of file_ops to which vscan on access scanning is applicable.
      - REST support requires ONTAP 9.15.1 or later.
    type: str
    version_added: 2.9.0

  unix_symlink:
    choices: ['local', 'widelink', 'disable']
    description:
      - The list of unix_symlink properties for this CIFS share
      - This option only supported with REST.
    type: str
    version_added: 21.19.0

  access_based_enumeration:
    description:
      - If enabled, all folders inside this share are visible to a user based on that individual user access right;
        prevents the display of folders or other shared resources that the user does not have access to.
      - This option only supported with REST.
    type: bool
    version_added: 22.3.0

  allow_unencrypted_access:
    description:
      - Specifies whether or not the SMB2 clients are allowed to access the encrypted share.
      - This option requires REST and ONTAP 9.11.0 or later.
    type: bool
    version_added: 22.3.0

  change_notify:
    description:
      - Specifies whether CIFS clients can request for change notifications for directories on this share.
      - This option only supported with REST.
    type: bool
    version_added: 22.3.0

  encryption:
    description:
      - Specifies that SMB encryption must be used when accessing this share. Clients that do not support encryption are not
        able to access this share.
      - This option only supported with REST.
    type: bool
    version_added: 22.3.0

  home_directory:
    description:
      - Specifies whether or not the share is a home directory share, where the share and path names are dynamic.
      - ONTAP home directory functionality automatically offer each user a dynamic share to their home directory without creating an
        individual SMB share for each user.
      - This feature enable us to configure a share that maps to different directories based on the user that connects to it
      - Instead of creating a separate shares for each user, a single share with a home directory parameters can be created.
      - In a home directory share, ONTAP dynamically generates the share-name and share-path by substituting
        %w, %u, and %d variables with the corresponding Windows user name, UNIX user name, and domain name, respectively.
      - This option only supported with REST and cannot modify.
    type: bool
    version_added: 22.3.0

  namespace_caching:
    description:
      - Specifies whether or not the SMB clients connecting to this share can cache the directory enumeration
        results returned by the CIFS servers.
      - This option requires REST and ONTAP 9.10.1 or later.
    type: bool
    version_added: 22.3.0

  oplocks:
    description:
      - Specify whether opportunistic locks are enabled on this share. "Oplocks" allow clients to lock files and cache content locally,
        which can increase performance for file operations.
      - Only supported with REST.
    type: bool
    version_added: 22.3.0

  show_snapshot:
    description:
      - Specifies whether or not the Snapshot copies can be viewed and traversed by clients.
      - This option requires REST and ONTAP 9.10.1 or later.
    type: bool
    version_added: 22.3.0

  continuously_available :
    description:
      - Specifies whether or not the clients connecting to this share can open files in a persistent manner.
      - Files opened in this way are protected from disruptive events, such as, failover and giveback.
      - This option requires REST and ONTAP 9.10.1 or later.
    type: bool
    version_added: 22.3.0

  browsable:
    description:
      - Specifies whether or not the Windows clients can browse the share.
      - This option requires REST and ONTAP 9.13.1 or later.
    type: bool
    version_added: 22.5.0

  show_previous_versions:
    description:
      - Specifies that the previous version can be viewed and restored from the client.
      - This option requires REST and ONTAP 9.13.1 or later.
    type: bool
    version_added: 22.5.0

  offline_files:
    choices: ['none', 'manual', 'documents', 'programs']
    description:
      - Allows Windows clients to cache data on this share.
      - This option is only supported with REST and requires ONTAP 9.10 or later.
    type: str
    version_added: 22.11.0

short_description: NetApp ONTAP Manage cifs-share
version_added: 2.6.0

'''

EXAMPLES = """
- name: Create CIFS share - ZAPI
  netapp.ontap.na_ontap_cifs:
    state: present
    name: cifsShareName
    path: /
    vserver: vserverName
    share_properties: browsable,oplocks
    symlink_properties: read_only,enable
    comment: CIFS share description
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Delete CIFS share - ZAPI
  netapp.ontap.na_ontap_cifs:
    state: absent
    name: cifsShareName
    vserver: vserverName
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Modify path CIFS share - ZAPI
  netapp.ontap.na_ontap_cifs:
    state: present
    name: pb_test
    vserver: vserverName
    path: /
    share_properties: show_previous_versions
    symlink_properties: disable
    vscan_fileop_profile: no_scan
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Create CIFS share - REST
  netapp.ontap.na_ontap_cifs:
    state: present
    name: cifsShareName
    path: /
    vserver: vserverName
    oplocks: true
    change_notify: true
    unix_symlink: disable
    comment: CIFS share description
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Modify CIFS share - REST
  netapp.ontap.na_ontap_cifs:
    state: present
    name: cifsShareName
    path: /
    vserver: vserverName
    oplocks: true
    change_notify: true
    unix_symlink: local
    comment: CIFS share description
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
"""

RETURN = """
"""

import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic


class NetAppONTAPCifsShare:
    """
    Methods to create/delete/modify(path) CIFS share
    """

    def __init__(self):
        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            name=dict(required=True, type='str', aliases=['share_name']),
            path=dict(required=False, type='str'),
            comment=dict(required=False, type='str'),
            vserver=dict(required=True, type='str'),
            unix_symlink=dict(required=False, type='str', choices=['local', 'widelink', 'disable']),
            share_properties=dict(required=False, type='list', elements='str'),
            symlink_properties=dict(required=False, type='list', elements='str'),
            vscan_fileop_profile=dict(required=False, type='str', choices=['no_scan', 'standard', 'strict', 'writes_only']),
            access_based_enumeration=dict(required=False, type='bool'),
            change_notify=dict(required=False, type='bool'),
            encryption=dict(required=False, type='bool'),
            home_directory=dict(required=False, type='bool'),
            oplocks=dict(required=False, type='bool'),
            show_snapshot=dict(required=False, type='bool'),
            allow_unencrypted_access=dict(required=False, type='bool'),
            namespace_caching=dict(required=False, type='bool'),
            continuously_available=dict(required=False, type='bool'),
            browsable=dict(required=False, type='bool'),
            show_previous_versions=dict(required=False, type='bool'),
            offline_files=dict(required=False, type='str', choices=['none', 'manual', 'documents', 'programs']),
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )

        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)

        # Set up Rest API
        self.rest_api = netapp_utils.OntapRestAPI(self.module)
        partially_supported_rest_properties = [['continuously_available', (9, 10, 1)], ['namespace_caching', (9, 10, 1)],
                                               ['show_snapshot', (9, 10, 1)], ['offline_files', (9, 10, 1)], ['allow_unencrypted_access', (9, 11)],
                                               ['browsable', (9, 13, 1)], ['show_previous_versions', (9, 13, 1)],
                                               ['vscan_fileop_profile', (9, 15, 1)]]
        unsupported_rest_properties = ['share_properties', 'symlink_properties']
        self.use_rest = self.rest_api.is_rest_supported_properties(self.parameters, unsupported_rest_properties, partially_supported_rest_properties)
        self.unsupported_zapi_properties = ['unix_symlink', 'access_based_enumeration', 'change_notify', 'encryption', 'home_directory',
                                            'oplocks', 'continuously_available', 'show_snapshot', 'namespace_caching', 'allow_unencrypted_access',
                                            'browsable', 'show_previous_versions', 'offline_files']
        self.svm_uuid = None
        if not self.use_rest:
            if not netapp_utils.has_netapp_lib():
                self.module.fail_json(msg=netapp_utils.netapp_lib_is_required())
            for unsupported_zapi_property in self.unsupported_zapi_properties:
                if self.parameters.get(unsupported_zapi_property) is not None:
                    msg = "Error: %s option is not supported with ZAPI.  It can only be used with REST." % unsupported_zapi_property
                    self.module.fail_json(msg=msg)
            self.server = netapp_utils.setup_na_ontap_zapi(module=self.module, vserver=self.parameters['vserver'])

    def get_cifs_share(self):
        """
        Return details about the cifs-share
        :param:
            name : Name of the cifs-share
        :return: Details about the cifs-share. None if not found.
        :rtype: dict
        """
        if self.use_rest:
            return self.get_cifs_share_rest()
        cifs_iter = netapp_utils.zapi.NaElement('cifs-share-get-iter')
        cifs_info = netapp_utils.zapi.NaElement('cifs-share')
        cifs_info.add_new_child('share-name', self.parameters.get('name'))
        cifs_info.add_new_child('vserver', self.parameters.get('vserver'))

        query = netapp_utils.zapi.NaElement('query')
        query.add_child_elem(cifs_info)

        cifs_iter.add_child_elem(query)

        result = self.server.invoke_successfully(cifs_iter, True)

        return_value = None
        # check if query returns the expected cifs-share
        if result.get_child_by_name('num-records') and \
                int(result.get_child_content('num-records')) == 1:
            properties_list = []
            symlink_list = []
            cifs_attrs = result.get_child_by_name('attributes-list').\
                get_child_by_name('cifs-share')
            if cifs_attrs.get_child_by_name('share-properties'):
                properties_attrs = cifs_attrs['share-properties']
                if properties_attrs is not None:
                    properties_list = [property.get_content() for property in properties_attrs.get_children()]
            if cifs_attrs.get_child_by_name('symlink-properties'):
                symlink_attrs = cifs_attrs['symlink-properties']
                if symlink_attrs is not None:
                    symlink_list = [symlink.get_content() for symlink in symlink_attrs.get_children()]
            return_value = {
                'share': cifs_attrs.get_child_content('share-name'),
                'path': cifs_attrs.get_child_content('path'),
                'share_properties': properties_list,
                'symlink_properties': symlink_list
            }
            value = cifs_attrs.get_child_content('comment')
            return_value['comment'] = value if value is not None else ''
            if cifs_attrs.get_child_by_name('vscan-fileop-profile'):
                return_value['vscan_fileop_profile'] = cifs_attrs['vscan-fileop-profile']

        return return_value

    def create_cifs_share(self):
        """
        Create CIFS share
        """
        options = {'share-name': self.parameters.get('name'),
                   'path': self.parameters.get('path')}
        cifs_create = netapp_utils.zapi.NaElement.create_node_with_children(
            'cifs-share-create', **options)
        self.create_modify_cifs_share(cifs_create, 'creating')

    def create_modify_cifs_share(self, zapi_request, action):
        if self.parameters.get('share_properties'):
            property_attrs = netapp_utils.zapi.NaElement('share-properties')
            zapi_request.add_child_elem(property_attrs)
            for aproperty in self.parameters.get('share_properties'):
                property_attrs.add_new_child('cifs-share-properties', aproperty)
        if self.parameters.get('symlink_properties'):
            symlink_attrs = netapp_utils.zapi.NaElement('symlink-properties')
            zapi_request.add_child_elem(symlink_attrs)
            for symlink in self.parameters.get('symlink_properties'):
                symlink_attrs.add_new_child('cifs-share-symlink-properties', symlink)
        if self.parameters.get('vscan_fileop_profile'):
            fileop_attrs = netapp_utils.zapi.NaElement('vscan-fileop-profile')
            fileop_attrs.set_content(self.parameters['vscan_fileop_profile'])
            zapi_request.add_child_elem(fileop_attrs)
        if self.parameters.get('comment'):
            zapi_request.add_new_child('comment', self.parameters['comment'])

        try:
            self.server.invoke_successfully(zapi_request,
                                            enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:

            self.module.fail_json(msg='Error %s cifs-share %s: %s'
                                  % (action, self.parameters.get('name'), to_native(error)),
                                  exception=traceback.format_exc())

    def delete_cifs_share(self):
        """
        Delete CIFS share
        """
        cifs_delete = netapp_utils.zapi.NaElement.create_node_with_children(
            'cifs-share-delete', **{'share-name': self.parameters.get('name')})

        try:
            self.server.invoke_successfully(cifs_delete, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error deleting cifs-share %s: %s'
                                  % (self.parameters.get('name'), to_native(error)),
                                  exception=traceback.format_exc())

    def modify_cifs_share(self):
        """
        modilfy path for the given CIFS share
        """
        options = {'share-name': self.parameters.get('name')}
        cifs_modify = netapp_utils.zapi.NaElement.create_node_with_children(
            'cifs-share-modify', **options)
        if self.parameters.get('path'):
            cifs_modify.add_new_child('path', self.parameters.get('path'))
        self.create_modify_cifs_share(cifs_modify, 'modifying')

    def get_cifs_share_rest(self):
        """
        get details of the CIFS share with rest API.
        """
        options = {'svm.name': self.parameters.get('vserver'),
                   'name': self.parameters.get('name'),
                   'fields': 'svm.uuid,'
                             'name,'
                             'path,'
                             'comment,'
                             'unix_symlink,'
                             'access_based_enumeration,'
                             'change_notify,'
                             'encryption,'
                             'oplocks,'}
        if self.rest_api.meets_rest_minimum_version(self.use_rest, 9, 10, 1):
            options['fields'] += 'show_snapshot,namespace_caching,continuously_available,offline_files,'
        if self.rest_api.meets_rest_minimum_version(self.use_rest, 9, 11, 0):
            options['fields'] += 'allow_unencrypted_access,'
        if self.rest_api.meets_rest_minimum_version(self.use_rest, 9, 13, 1):
            options['fields'] += 'browsable,show_previous_versions,'
        if self.rest_api.meets_rest_minimum_version(self.use_rest, 9, 15, 1):
            options['fields'] += 'vscan_profile,'
        api = 'protocols/cifs/shares'
        record, error = rest_generic.get_one_record(self.rest_api, api, options)
        if error:
            self.module.fail_json(msg="Error on fetching cifs shares: %s" % error)
        if record:
            self.svm_uuid = record['svm']['uuid']
            return {
                'path': record['path'],
                'comment': record.get('comment', ''),
                'unix_symlink': record.get('unix_symlink', ''),
                'access_based_enumeration': record.get('access_based_enumeration'),
                'change_notify': record.get('change_notify'),
                'encryption': record.get('encryption'),
                'oplocks': record.get('oplocks'),
                'continuously_available': record.get('continuously_available'),
                'offline_files': record.get('offline_files'),
                'show_snapshot': record.get('show_snapshot'),
                'namespace_caching': record.get('namespace_caching'),
                'allow_unencrypted_access': record.get('allow_unencrypted_access'),
                'browsable': record.get('browsable'),
                'show_previous_versions': record.get('show_previous_versions'),
                'vscan_fileop_profile': record.get('vscan_profile')
            }
        return None

    def create_modify_body_rest(self, params=None):
        body = {}
        # modify is set in params, if not assign self.parameters for create.
        if params is None:
            params = self.parameters
        options = ['path', 'comment', 'unix_symlink', 'access_based_enumeration', 'change_notify', 'encryption',
                   'home_directory', 'oplocks', 'continuously_available', 'offline_files', 'show_snapshot', 'namespace_caching',
                   'allow_unencrypted_access', 'browsable', 'show_previous_versions', 'vscan_fileop_profile']
        for key in options:
            if key in params:
                if key == 'vscan_fileop_profile':
                    body['vscan_profile'] = params[key]
                else:
                    body[key] = params[key]
        return body

    def create_cifs_share_rest(self):
        """
        create CIFS share with rest API.
        """
        if not self.use_rest:
            return self.create_cifs_share()
        body = self.create_modify_body_rest()
        if 'vserver' in self.parameters:
            body['svm.name'] = self.parameters['vserver']
        if 'name' in self.parameters:
            body['name'] = self.parameters['name']
        if 'path' in self.parameters:
            body['path'] = self.parameters['path']
        api = 'protocols/cifs/shares'
        dummy, error = rest_generic.post_async(self.rest_api, api, body)
        if error is not None:
            self.module.fail_json(msg="Error on creating cifs shares: %s" % error)

    def delete_cifs_share_rest(self):
        """
        delete CIFS share with rest API.
        """
        if not self.use_rest:
            return self.delete_cifs_share()
        body = {'name': self.parameters.get('name')}
        api = 'protocols/cifs/shares'
        dummy, error = rest_generic.delete_async(self.rest_api, api, self.svm_uuid, body)
        if error is not None:
            self.module.fail_json(msg=" Error on deleting cifs shares: %s" % error)

    def modify_cifs_share_rest(self, modify):
        """
        modilfy the given CIFS share with rest API.
        """
        if not self.use_rest:
            return self.modify_cifs_share()
        api = 'protocols/cifs/shares/%s' % self.svm_uuid
        body = self.create_modify_body_rest(modify)
        if body:
            dummy, error = rest_generic.patch_async(self.rest_api, api, self.parameters['name'], body)
            if error is not None:
                self.module.fail_json(msg="Error on modifying cifs shares: %s" % error)

    def apply(self):
        '''Apply action to cifs share'''
        current = self.get_cifs_share()
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        # ZAPI accepts both 'show-previous-versions' and 'show_previous_versions', but only returns the latter
        if not self.use_rest and cd_action is None and 'show-previous-versions' in self.parameters.get('share_properties', [])\
           and current and 'show_previous_versions' in current.get('share_properties', []):
            self.parameters['share_properties'].remove('show-previous-versions')
            self.parameters['share_properties'].append('show_previous_versions')
        modify = self.na_helper.get_modified_attributes(current, self.parameters) if cd_action is None else None

        if self.na_helper.changed and not self.module.check_mode:
            if cd_action == 'create':
                self.create_cifs_share_rest()
            elif cd_action == 'delete':
                self.delete_cifs_share_rest()
            elif modify:
                self.modify_cifs_share_rest(modify)
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action, modify)
        self.module.exit_json(**result)


def main():
    '''Execute action from playbook'''
    cifs_obj = NetAppONTAPCifsShare()
    cifs_obj.apply()


if __name__ == '__main__':
    main()
