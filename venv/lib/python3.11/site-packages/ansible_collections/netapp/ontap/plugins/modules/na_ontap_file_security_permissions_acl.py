#!/usr/bin/python

# (c) 2022-2025, NetApp, Inc
# GNU General Public License v3.0+  (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
module: na_ontap_file_security_permissions_acl
short_description: NetApp ONTAP file security permissions ACL
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap_rest
version_added: 22.0.0
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
  - Add, delete, or modify a file_security_permissions ACL on NetApp ONTAP.
  - Note that ACLs are mached based on ('user', 'access', 'access_control', 'apply_to').
    To modify any of these 4 properties, you would need to delete the ACL and create a new one.
    Or use C(netapp.ontap.na_ontap_file_security_permissions).

options:
  state:
    description:
      - Whether the specified file security permissions ACL should exist or not.
    choices: ['present', 'absent']
    type: str
    default: 'present'

  path:
    description:
      - The path of the file or directory on which to apply security permissions.
    type: str
    required: true

  vserver:
    description:
      - Name of the vserver to use.
    type: str
    required: true

  access_control:
    description:
      - An Access Control Level specifies the access control of the task to be applied.
      - Valid values are "file-directory" or "Storage-Level Access Guard (SLAG)".
      - SLAG is used to apply the specified security descriptors with the task for the volume or qtree.
      - Otherwise, the security descriptors are applied on files and directories at the specified path.
      - The value slag is not supported on FlexGroups volumes. The default value is "file-directory".
      - This field requires ONTAP 9.10.1 or later.  This defaults to "file_directory".
    choices: ['file_directory', 'slag']
    type: str
  access:
    description:
      - An ACE is an element in an access control list (ACL). An ACL can have zero or more ACEs.
      - Each ACE controls or monitors access to an object by a specified trustee.
    choices: ['access_allow', 'access_deny', 'audit_failure', 'audit_success']
    type: str
    required: true
  acl_user:
    description:
      - Specifies the account to which the ACE applies. Specify either name or SID.
      - As of 22.0.0, the module is not idempotent when using a SID.
      - Note - we cannot use C(user) as if conflicts with the option for the admin user.
    type: str
    required: true
  rights:
    description:
      - Specifies the access right controlled by the ACE for the account specified.
      - The "rights" parameter is mutually exclusive with the "advanced_rights" parameter.
      - ONTAP translates rights into advanced_rights and this module is not idempotent when rights are used.
      - Make sure to use C(advanced_rights) to maintain idempotency.  C(rights) can be used to discover the mapping to C(advanced_rights).
    choices: ['no_access', 'full_control', 'modify', 'read_and_execute', 'read', 'write']
    type: str
  apply_to:
    description:
      - Specifies where to apply the DACL or SACL entries.
      - With SLAGs, ONTAP accepts the three suboptions to be set to true, but creates 2 ACLs.
        This module requires the 2 ACLs to be present to preserve idempotency.
        See also C(validate_changes).
    type: dict
    required: true
    suboptions:
      files:
        description:
          - Apply to Files.
        type: bool
        default: false
      sub_folders:
        description:
          - Apply to all sub-folders.
        type: bool
        default: false
      this_folder:
        description:
          - Apply only to this folder
        type: bool
        default: false
  advanced_rights:
    description:
      - Specifies the advanced access right controlled by the ACE for the account specified.
    type: dict
    suboptions:
      append_data:
        description:
          - Append Data.
        type: bool
        required: false
      delete:
        description:
          - Delete.
        type: bool
        required: false
      delete_child:
        description:
          - Delete Child.
        type: bool
        required: false
      execute_file:
        description:
          - Execute File.
        type: bool
        required: false
      full_control:
        description:
          - Full Control.
        type: bool
        required: false
      read_attr:
        description:
          - Read Attributes.
        type: bool
        required: false
      read_data:
        description:
          - Read Data.
        type: bool
        required: false
      read_ea:
        description:
          - Read Extended Attributes.
        type: bool
        required: false
      read_perm:
        description:
          - Read Permissions.
        type: bool
        required: false
      write_attr:
        description:
          - Write Attributes.
        type: bool
        required: false
      write_data:
        description:
          - Write Data.
        type: bool
        required: false
      write_ea:
        description:
          - Write Extended Attributes.
        type: bool
        required: false
      write_owner:
        description:
          - Write Owner.
        type: bool
        required: false
      write_perm:
        description:
          - Write Permission.
        type: bool
        required: false
  ignore_paths:
    description:
      - For each file or directory in the list, specifies that permissions on this file or directory cannot be replaced.
    type: list
    elements: str
  propagation_mode:
    description:
      - Specifies how to propagate security settings to child subfolders and files.
      - Defaults to propagate.
      - This option is valid in create, but cannot modify.
    choices: ['propagate', 'replace']
    type: str

  validate_changes:
    description:
      - ACLs may not be applied as expected.
      - For instance, if Everyone is inherited will all permissions, additional users will be granted all permissions, regardless of the request.
      - For this specific example, you can either delete the top level Everyone, or create a new ACL for Everyone at a lower level.
      - When using C(rights), ONTAP translates them into C(advanced_rights) so the validation will always fail.
      - Valid values are C(ignore), no checking; C(warn) to issue a warning; C(error) to fail the module.
      - With SLAGS, ONTAP may split one ACL into two ACLs depending on the C(apply_to) settings.  To maintain idempotency, please provide 2 ACLs as input.
    choices: ['ignore', 'warn', 'error']
    type: str
    default: error

notes:
  - Supports check_mode.
  - Only supported with REST and requires ONTAP 9.9.1 or later.
  - SLAG requires ONTAP 9.10.1 or later.
'''

EXAMPLES = """
- name: Add ACL for file or directory security permissions.
  netapp.ontap.na_ontap_file_security_permissions_acl:
    vserver: "{{ vserver_name }}"
    access_control: file_directory
    path: "{{ file_mount_path }}"
    validate_changes: warn
    access: access_allow
    # Note, without quotes, use a single backslash in AD user names
    # with quotes, it needs to be escaped as a double backslash
    # user: "ANSIBLE_CIFS\\user1"
    # we can't show an example with a single backslash as this is a python file, but it works in YAML.
    acl_user: "user1"
    apply_to:
      this_folder: true
    advanced_rights:
      append_data: true
      delete: false

- name: Modify ACL for file or directory security permissions.
  netapp.ontap.na_ontap_file_security_permissions_acl:
    vserver: "{{ vserver_name }}"
    access_control: file_directory
    path: "{{ file_mount_path }}"
    validate_changes: warn
    access: access_allow
    acl_user: "user1"
    apply_to:
      this_folder: true
    advanced_rights:
      append_data: false
      delete: true

- name: Delete ACL for file or directory security permissions.
  netapp.ontap.na_ontap_file_security_permissions_acl:
    vserver: "{{ vserver_name }}"
    access_control: file_directory
    path: "{{ file_mount_path }}"
    validate_changes: warn
    access: access_allow
    acl_user: "user1"
    apply_to:
      this_folder: true
    state: absent
"""

RETURN = """
"""

import traceback
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic, rest_vserver


class NetAppOntapFileSecurityPermissionsACL:
    def __init__(self):
        self.argument_spec = netapp_utils.na_ontap_rest_only_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            vserver=dict(required=True, type='str'),
            path=dict(required=True, type='str'),
            access_control=dict(required=False, type='str', choices=['file_directory', 'slag']),
            access=dict(required=True, choices=['access_allow', 'access_deny', 'audit_failure', 'audit_success'], type='str'),
            apply_to=dict(required=True, type='dict', options=dict(
                files=dict(required=False, type='bool', default=False),
                sub_folders=dict(required=False, type='bool', default=False),
                this_folder=dict(required=False, type='bool', default=False),
            )),
            advanced_rights=dict(required=False, type='dict', options=dict(
                append_data=dict(required=False, type='bool'),
                delete=dict(required=False, type='bool'),
                delete_child=dict(required=False, type='bool'),
                execute_file=dict(required=False, type='bool'),
                full_control=dict(required=False, type='bool'),
                read_attr=dict(required=False, type='bool'),
                read_data=dict(required=False, type='bool'),
                read_ea=dict(required=False, type='bool'),
                read_perm=dict(required=False, type='bool'),
                write_attr=dict(required=False, type='bool'),
                write_data=dict(required=False, type='bool'),
                write_ea=dict(required=False, type='bool'),
                write_owner=dict(required=False, type='bool'),
                write_perm=dict(required=False, type='bool'),
            )),
            ignore_paths=dict(required=False, type='list', elements='str'),
            propagation_mode=dict(required=False, type='str', choices=['propagate', 'replace']),
            rights=dict(required=False,
                        choices=['no_access', 'full_control', 'modify', 'read_and_execute', 'read', 'write'],
                        type='str'),
            acl_user=dict(required=True, type='str'),
            validate_changes=dict(required=False, type='str', choices=['ignore', 'warn', 'error'], default='error'),
        ))
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )
        self.svm_uuid = None
        self.na_helper = NetAppModule(self.module)
        self.parameters = self.na_helper.check_and_set_parameters(self.module)
        self.rest_api = netapp_utils.OntapRestAPI(self.module)
        self.rest_api.fail_if_not_rest_minimum_version('na_ontap_file_security_permissions_acl', 9, 9, 1)
        dummy, error = self.rest_api.is_rest(partially_supported_rest_properties=[['access_control', (9, 10, 1)]], parameters=self.parameters)
        self.apply_to_keys = ['files', 'sub_folders', 'this_folder']
        if self.parameters['state'] == 'present':
            self.validate_acl()
        self.parameters['user'] = self.parameters['acl_user']

    def validate_acl(self):
        self.parameters = self.na_helper.filter_out_none_entries(self.parameters)
        if 'rights' in self.parameters:
            if 'advanced_rights' in self.parameters:
                self.module.fail_json(msg="Error: suboptions 'rights' and 'advanced_rights' are mutually exclusive.")
            self.module.warn('This module is not idempotent when "rights" is used, make sure to use "advanced_rights".')
        # validate that at least one suboption is true
        if not any(self.na_helper.safe_get(self.parameters, ['apply_to', key]) for key in self.apply_to_keys):
            self.module.fail_json(msg="Error: at least one suboption must be true for apply_to.  Got: %s" % self.parameters.get('apply_to'))

    @staticmethod
    def url_encode(url_fragment):
        """
            replace special characters with URL encoding:
            %2F for /, %5C for backslash
        """
        # \ is the escape character in python, so \\ means \
        return url_fragment.replace("/", "%2F").replace("\\", "%5C")

    def get_svm_uuid(self):
        self.svm_uuid, dummy = rest_vserver.get_vserver_uuid(self.rest_api, self.parameters['vserver'], self.module, True)

    def get_file_security_permissions_acl(self):
        """ we cannot get a single ACL - get a list, and find ours"""
        api = 'protocols/file-security/permissions/%s/%s' % (self.svm_uuid, self.url_encode(self.parameters['path']))
        fields = 'acls'
        record, error = rest_generic.get_one_record(self.rest_api, api, fields=fields)
        # If we get 655865 the path we gave was not found, so we don't want to fail we want to return None
        if error:
            if '655865' in error and self.parameters['state'] == 'absent':
                return None
            self.module.fail_json(msg="Error fetching file security permissions %s: %s" % (self.parameters['path'], to_native(error)),
                                  exception=traceback.format_exc())
        if record and 'acls' in record:
            record = self.form_current(record)
            return self.match_acl_with_acls(self.parameters, record['acls'])
        return None

    def form_current(self, record):
        current = {
            'group': self.na_helper.safe_get(record, ['group']),
            'owner': self.na_helper.safe_get(record, ['owner']),
            'control_flags': self.na_helper.safe_get(record, ['control_flags']),
            'path': record['path']
        }
        acls = []

        def form_acl(acl):
            advanced_rights_keys = ['append_data', 'delete', 'delete_child', 'execute_file', 'full_control', 'read_attr',
                                    'read_data', 'read_ea', 'read_perm', 'write_attr', 'write_data', 'write_ea', 'write_owner', 'write_perm']
            advanced_rights = {}
            apply_to = {}
            if 'advanced_rights' in acl:
                for key in advanced_rights_keys:
                    # REST does not return the keys when the value is False
                    advanced_rights[key] = acl['advanced_rights'].get(key, False)
            if 'apply_to' in acl:
                for key in self.apply_to_keys:
                    # REST does not return the keys when the value is False
                    apply_to[key] = acl['apply_to'].get(key, False)
            return {
                'advanced_rights': advanced_rights or None,
                'apply_to': apply_to or None
            }

        for acl in record.get('acls', []):
            each_acl = {
                'access': self.na_helper.safe_get(acl, ['access']),
                'access_control': self.na_helper.safe_get(acl, ['access_control']),
                'inherited': self.na_helper.safe_get(acl, ['inherited']),
                'rights': self.na_helper.safe_get(acl, ['rights']),
                'user': self.na_helper.safe_get(acl, ['user']),
            }
            each_acl.update(form_acl(acl))
            acls.append(each_acl)
        current['acls'] = acls or None
        return current

    def build_body(self, action):
        keys = {
            'create': ['access', 'access_control', 'advanced_rights', 'apply_to', 'ignore_paths', 'propagation_mode', 'rights', 'user'],
            'modify': ['access', 'access_control', 'advanced_rights', 'apply_to', 'ignore_paths', 'rights'],
            'delete': ['access', 'access_control', 'apply_to', 'ignore_paths', 'propagation_mode'],
            # 'delete': ['access', 'access_control', 'ignore_paths', 'propagation_mode'],
        }
        if action not in keys:
            self.module.fail_json(msg='Internal error - unexpected action %s' % action)
        body = {}
        for key in keys[action]:
            if key in self.parameters:
                body[key] = self.parameters[key]
        return body

    def create_file_security_permissions_acl(self):
        api = 'protocols/file-security/permissions/%s/%s/acl' % (self.svm_uuid, self.url_encode(self.parameters['path']))
        body = self.build_body('create')
        dummy, error = rest_generic.post_async(self.rest_api, api, body, timeout=0)
        if error:
            self.module.fail_json(msg='Error creating file security permissions acl %s: %s' % (self.parameters['path'], to_native(error)),
                                  exception=traceback.format_exc())

    def modify_file_security_permissions_acl(self):
        api = 'protocols/file-security/permissions/%s/%s/acl' % (self.svm_uuid, self.url_encode(self.parameters['path']))
        body = self.build_body('modify')
        dummy, error = rest_generic.patch_async(self.rest_api, api, self.url_encode(self.parameters['user']), body)
        if error:
            self.module.fail_json(msg='Error modifying file security permissions acl %s: %s' % (self.parameters['path'], to_native(error)),
                                  exception=traceback.format_exc())

    def delete_file_security_permissions_acl(self):
        api = 'protocols/file-security/permissions/%s/%s/acl' % (self.svm_uuid, self.url_encode(self.parameters['path']))
        body = self.build_body('delete')
        dummy, error = rest_generic.delete_async(self.rest_api, api, self.url_encode(self.parameters['user']), body=body, timeout=0)
        if error:
            self.module.fail_json(msg='Error deleting file security permissions acl %s: %s' % (self.parameters['path'], to_native(error)),
                                  exception=traceback.format_exc())

    def match_acl_with_acls(self, acl, acls):
        """ return acl if user and access and apply_to are matched, otherwiese None """
        matches = []
        for an_acl in acls:
            # with 9.9.1, access_control is not supported.  It will be set to None in received ACLs, and omitted in desired ACLs
            # but we can assume the user would like to see file_directory.
            # We can't modify inherited ACLs.  But we can create a new one at a lower scope.
            inherited = an_acl['inherited'] if 'inherited' in an_acl else False and (acl['inherited'] if 'inherited' in acl else False)
            if (acl['user'] == an_acl['user']
                    and acl['access'] == an_acl['access']
                    and acl.get('access_control', 'file_directory') == an_acl.get('access_control', 'file_directory')
                    and acl['apply_to'] == an_acl['apply_to']
                    and not inherited):
                matches.append(an_acl)
        if len(matches) > 1:
            self.module.fail_json(msg='Error matching ACLs, found more than one match.  Found %s' % matches)
        return matches[0] if matches else None

    def get_actions(self):
        current = self.get_file_security_permissions_acl()
        modify = None
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        if cd_action is None and self.parameters['state'] == 'present':
            modify = self.na_helper.get_modified_attributes(current, self.parameters)
        return cd_action, modify

    def apply(self):
        self.get_svm_uuid()
        cd_action, modify = self.get_actions()

        if self.na_helper.changed and not self.module.check_mode:
            if cd_action == 'create':
                self.create_file_security_permissions_acl()
            if cd_action == 'delete':
                self.delete_file_security_permissions_acl()
            if modify:
                self.modify_file_security_permissions_acl()
            self.validate_changes(cd_action, modify)
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action, modify)
        self.module.exit_json(**result)

    def validate_changes(self, cd_action, modify):
        if self.parameters['validate_changes'] == 'ignore':
            return
        new_cd_action, new_modify = self.get_actions()
        errors = []
        if new_cd_action is not None:
            errors.append('%s still required after %s (with modify: %s)' % (new_cd_action, cd_action, modify))
        if new_modify:
            errors.append('modify: %s still required after %s' % (new_modify, modify))
        if errors:
            msg = 'Error - %s' % ' - '.join(errors)
            if self.parameters['validate_changes'] == 'error':
                self.module.fail_json(msg=msg)
            if self.parameters['validate_changes'] == 'warn':
                self.module.warn(msg)


def main():
    """Apply volume operations from playbook"""
    obj = NetAppOntapFileSecurityPermissionsACL()
    obj.apply()


if __name__ == '__main__':
    main()
