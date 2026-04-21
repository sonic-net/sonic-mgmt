#!/usr/bin/python

# (c) 2018-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

'''
na_ontap_qtree
'''

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = '''

module: na_ontap_qtree

short_description: NetApp ONTAP manage qtrees
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap
version_added: 2.6.0
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>

description:
  - Create/Modify/Delete Qtrees.

options:

  state:
    description:
      - Whether the specified qtree should exist or not.
    choices: ['present', 'absent']
    type: str
    default: 'present'

  name:
    description:
      - The name of the qtree to manage.
      - With REST, this can also be a path.
    required: true
    type: str

  from_name:
    description:
      - Name of the qtree to be renamed.
    version_added: 2.7.0
    type: str

  flexvol_name:
    description:
      - The name of the FlexVol the qtree should exist on.
    required: true
    type: str

  vserver:
    description:
      - The name of the vserver to use.
    required: true
    type: str

  export_policy:
    description:
      - The name of the export policy to apply.
    version_added: 2.9.0
    type: str

  security_style:
    description:
      - The security style for the qtree.
    choices: ['unix', 'ntfs', 'mixed']
    type: str
    version_added: 2.9.0

  oplocks:
    description:
      - Whether the oplocks should be enabled or not for the qtree.
    choices: ['enabled', 'disabled']
    type: str
    version_added: 2.9.0

  unix_permissions:
    description:
      - File permissions bits of the qtree.
      - Accepts either octal or string format.
      - Examples 0777, 777 in octal and ---rwxrwxrwx, sstrwxrwxrwx, rwxrwxrwx in string format.
    version_added: 2.9.0
    type: str

  force_delete:
    description:
      - Whether the qtree should be deleted even if files still exist.
      - Note that the default of true reflect the REST API behavior.
      - a value of false is not supported with REST.
    type: bool
    default: true
    version_added: 20.8.0

  wait_for_completion:
    description:
      - Only applicable for REST.  When using ZAPI, the deletion is always synchronous.
      - Deleting a qtree may take time if many files need to be deleted.
      - Set this parameter to 'true' for synchronous execution during delete.
      - Set this parameter to 'false' for asynchronous execution.
      - For asynchronous, execution exits as soon as the request is sent, and the qtree is deleted in background.
    type: bool
    default: true
    version_added: 2.9.0

  time_out:
    description:
      - Maximum time to wait for qtree deletion in seconds when wait_for_completion is True.
      - Error out if task is not completed in defined time.
      - Default is set to 3 minutes.
    default: 180
    type: int
    version_added: 2.9.0

  unix_user:
    description:
      - The user set as owner of the qtree.
      - Only supported with REST and ONTAP 9.9 or later.
    type: str
    version_added: 21.21.0

  unix_group:
    description:
      - The group set as owner of the qtree.
      - Only supported with REST and ONTAP 9.9 or later.
    type: str
    version_added: 21.21.0

'''

EXAMPLES = """
- name: Create Qtrees.
  netapp.ontap.na_ontap_qtree:
    state: present
    name: ansibleQTree
    flexvol_name: ansibleVolume
    export_policy: policyName
    security_style: mixed
    oplocks: disabled
    unix_permissions: 777
    vserver: ansibleVServer
    unix_user: user1
    unix_group: group1
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Rename Qtrees.
  netapp.ontap.na_ontap_qtree:
    state: present
    from_name: ansibleQTree
    name: ansibleQTree_rename
    flexvol_name: ansibleVolume
    vserver: ansibleVServer
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: modify Qtrees unix_permissions using string format.
  netapp.ontap.na_ontap_qtree:
    state: present
    name: ansibleQTree_rename
    flexvol_name: ansibleVolume
    vserver: ansibleVServer
    unix_permissions: sstrwxrwxrwx
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: delete Qtrees.
  netapp.ontap.na_ontap_qtree:
    state: absent
    name: ansibleQTree_rename
    vserver: ansibleVServer
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
from ansible_collections.netapp.ontap.plugins.module_utils.netapp import OntapRestAPI
import ansible_collections.netapp.ontap.plugins.module_utils.rest_response_helpers as rrh
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic


class NetAppOntapQTree:
    '''Class with qtree operations'''

    def __init__(self):
        self.use_rest = False
        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            name=dict(required=True, type='str'),
            from_name=dict(required=False, type='str'),
            flexvol_name=dict(required=True, type='str'),
            vserver=dict(required=True, type='str'),
            export_policy=dict(required=False, type='str'),
            security_style=dict(required=False, type='str', choices=['unix', 'ntfs', 'mixed']),
            oplocks=dict(required=False, type='str', choices=['enabled', 'disabled']),
            unix_permissions=dict(required=False, type='str'),
            force_delete=dict(required=False, type='bool', default=True),
            wait_for_completion=dict(required=False, type='bool', default=True),
            time_out=dict(required=False, type='int', default=180),
            unix_user=dict(required=False, type='str'),
            unix_group=dict(required=False, type='str')
        ))
        self.volume_uuid, self.qid = None, None
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            required_if=[
                ('state', 'present', ['flexvol_name'])
            ],
            supports_check_mode=True
        )
        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)

        self.rest_api = OntapRestAPI(self.module)
        unsupported_rest_properties = ['oplocks']
        partially_supported_rest_properties = [['unix_user', (9, 9)], ['unix_group', (9, 9)]]
        self.use_rest = self.rest_api.is_rest_supported_properties(self.parameters, unsupported_rest_properties, partially_supported_rest_properties)
        if not self.use_rest:
            if not netapp_utils.has_netapp_lib():
                self.module.fail_json(msg=netapp_utils.netapp_lib_is_required())
            self.server = netapp_utils.setup_na_ontap_zapi(module=self.module, vserver=self.parameters['vserver'])

    def get_qtree(self, name=None):
        """
        Checks if the qtree exists.
        :param:
            name : qtree name
        :return:
            Details about the qtree
            False if qtree is not found
        :rtype: bool
        """
        if name is None:
            name = self.parameters['name']
        if self.use_rest:
            api = "storage/qtrees"
            query = {'fields': 'export_policy,unix_permissions,security_style,volume',
                     'svm.name': self.parameters['vserver'],
                     'volume': self.parameters['flexvol_name'],
                     'name': '"' + name + '"'}
            if 'unix_user' in self.parameters:
                query['fields'] += ',user.name'
            if 'unix_group' in self.parameters:
                query['fields'] += ',group.name'
            record, error = rest_generic.get_one_record(self.rest_api, api, query)
            if error:
                msg = "Error fetching qtree: %s" % error
                self.module.fail_json(msg=msg)
            if record:
                self.volume_uuid = record['volume']['uuid']
                self.qid = str(record['id'])
                return {
                    'name': record['name'],
                    'export_policy': self.na_helper.safe_get(record, ['export_policy', 'name']),
                    'security_style': self.na_helper.safe_get(record, ['security_style']),
                    'unix_permissions': str(self.na_helper.safe_get(record, ['unix_permissions'])),
                    'unix_user': self.na_helper.safe_get(record, ['user', 'name']),
                    'unix_group': self.na_helper.safe_get(record, ['group', 'name'])
                }
            return None

        qtree_list_iter = netapp_utils.zapi.NaElement('qtree-list-iter')
        query_details = netapp_utils.zapi.NaElement.create_node_with_children(
            'qtree-info', **{'vserver': self.parameters['vserver'],
                             'volume': self.parameters['flexvol_name'],
                             'qtree': name})
        query = netapp_utils.zapi.NaElement('query')
        query.add_child_elem(query_details)
        qtree_list_iter.add_child_elem(query)
        try:
            result = self.server.invoke_successfully(qtree_list_iter, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error fetching qtree: %s' % to_native(error),
                                  exception=traceback.format_exc())
        return_q = None
        if (result.get_child_by_name('num-records') and int(result.get_child_content('num-records')) >= 1):
            return_q = {'export_policy': result['attributes-list']['qtree-info']['export-policy'],
                        'oplocks': result['attributes-list']['qtree-info']['oplocks'],
                        'security_style': result['attributes-list']['qtree-info']['security-style']}

            value = self.na_helper.safe_get(result, ['attributes-list', 'qtree-info', 'mode'])
            return_q['unix_permissions'] = value if value is not None else ''

        return return_q

    def create_qtree(self):
        """
        Create a qtree
        """
        if self.use_rest:
            api = "storage/qtrees"
            body = {'volume': {'name': self.parameters['flexvol_name']},
                    'svm': {'name': self.parameters['vserver']}}
            body.update(self.form_create_modify_body_rest())
            query = dict(return_timeout=10)
            dummy, error = rest_generic.post_async(self.rest_api, api, body, query)
            if error:
                if "job reported error:" in error and "entry doesn't exist" in error:
                    # ignore RBAC issue with FSx - BURT1525998
                    self.module.warn('Ignoring job status, assuming success.')
                    return
                self.module.fail_json(msg='Error creating qtree %s: %s' % (self.parameters['name'], error))
        else:
            self.create_or_modify_qtree_zapi('qtree-create', "Error creating qtree %s: %s")

    def delete_qtree(self):
        """
        Delete a qtree
        """
        if self.use_rest:
            api = "storage/qtrees/%s" % self.volume_uuid
            query = {'return_timeout': 120}
            response, error = rest_generic.delete_async(self.rest_api, api, self.qid, query)
            if self.parameters['wait_for_completion']:
                dummy, error = rrh.check_for_error_and_job_results(api, response, error, self.rest_api)
            if error:
                if not self.parameters['wait_for_completion'] and \
                        'job reported error:' in error and 'Timeout error: Process still running' in error:
                    self.module.warn("Process is still running in the background, exiting with no further waiting as 'wait_for_completion' is set to false.")
                    return
                self.module.fail_json(msg='Error deleting qtree %s: %s' % (self.parameters['name'], error))

        else:
            path = '/vol/%s/%s' % (self.parameters['flexvol_name'], self.parameters['name'])
            options = {'qtree': path}
            if self.parameters['force_delete']:
                options['force'] = "true"
            qtree_delete = netapp_utils.zapi.NaElement.create_node_with_children(
                'qtree-delete', **options)

            try:
                self.server.invoke_successfully(qtree_delete,
                                                enable_tunneling=True)
            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(msg="Error deleting qtree %s: %s" % (path, to_native(error)),
                                      exception=traceback.format_exc())

    def rename_qtree(self):
        """
        Rename a qtree
        """
        if self.use_rest:
            error = 'Internal error, use modify with REST'
            self.module.fail_json(msg=error)
        else:
            path = '/vol/%s/%s' % (self.parameters['flexvol_name'], self.parameters['from_name'])
            new_path = '/vol/%s/%s' % (self.parameters['flexvol_name'], self.parameters['name'])
            qtree_rename = netapp_utils.zapi.NaElement.create_node_with_children(
                'qtree-rename', **{'qtree': path,
                                   'new-qtree-name': new_path})

            try:
                self.server.invoke_successfully(qtree_rename,
                                                enable_tunneling=True)
            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(msg="Error renaming qtree %s: %s"
                                      % (self.parameters['from_name'], to_native(error)),
                                      exception=traceback.format_exc())

    def modify_qtree(self):
        """
        Modify a qtree
        """
        if self.use_rest:
            body = self.form_create_modify_body_rest()
            api = "storage/qtrees/%s" % self.volume_uuid
            query = dict(return_timeout=10)
            dummy, error = rest_generic.patch_async(self.rest_api, api, self.qid, body, query)
            if error:
                self.module.fail_json(msg='Error modifying qtree %s: %s' % (self.parameters['name'], error))
        else:
            self.create_or_modify_qtree_zapi('qtree-modify', 'Error modifying qtree %s: %s')

    def create_or_modify_qtree_zapi(self, zapi_request_name, error_message):
        options = {'qtree': self.parameters['name'], 'volume': self.parameters['flexvol_name']}

        if self.parameters.get('export_policy'):
            options['export-policy'] = self.parameters['export_policy']
        if self.parameters.get('security_style'):
            options['security-style'] = self.parameters['security_style']
        if self.parameters.get('oplocks'):
            options['oplocks'] = self.parameters['oplocks']
        if self.parameters.get('unix_permissions'):
            options['mode'] = self.parameters['unix_permissions']
        zapi_request = netapp_utils.zapi.NaElement.create_node_with_children(zapi_request_name, **options)

        try:
            self.server.invoke_successfully(zapi_request, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg=(error_message % (self.parameters['name'], to_native(error))), exception=traceback.format_exc())

    def form_create_modify_body_rest(self):
        body = {'name': self.parameters['name']}
        if self.parameters.get('security_style'):
            body['security_style'] = self.parameters['security_style']
        if self.parameters.get('unix_permissions'):
            body['unix_permissions'] = self.parameters['unix_permissions']
        if self.parameters.get('export_policy'):
            body['export_policy'] = {'name': self.parameters['export_policy']}
        if self.parameters.get('unix_user'):
            body['user'] = {'name': self.parameters['unix_user']}
        if self.parameters.get('unix_group'):
            body['group'] = {'name': self.parameters['unix_group']}
        return body

    def apply(self):
        '''Call create/delete/modify/rename operations'''
        current = self.get_qtree()
        rename, cd_action, modify = None, None, None
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        if cd_action == 'create' and self.parameters.get('from_name'):
            current = self.get_qtree(self.parameters['from_name'])
            if current is None:
                self.module.fail_json(msg="Error renaming: qtree %s does not exist" % self.parameters['from_name'])
            cd_action = None
            if not self.use_rest:
                # modify can change the name for REST, as UUID is the key.
                rename = True

        if cd_action is None:
            octal_value = current.get('unix_permissions') if current else None
            if self.parameters.get('unix_permissions')\
                    and self.na_helper.compare_chmod_value(octal_value, self.parameters['unix_permissions']):
                del self.parameters['unix_permissions']
            modify = self.na_helper.get_modified_attributes(current, self.parameters)

        if self.use_rest and cd_action == 'delete' and not self.parameters['force_delete']:
            self.module.fail_json(msg='Error: force_delete option is not supported for REST, unless set to true.')

        if self.na_helper.changed and not self.module.check_mode:
            if cd_action == 'create':
                self.create_qtree()
            elif cd_action == 'delete':
                self.delete_qtree()
            else:
                if rename:
                    self.rename_qtree()
                if modify:
                    self.modify_qtree()
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action, modify)
        self.module.exit_json(**result)


def main():
    '''Apply qtree operations from playbook'''
    qtree_obj = NetAppOntapQTree()
    qtree_obj.apply()


if __name__ == '__main__':
    main()
