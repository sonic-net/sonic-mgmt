#!/usr/bin/python

# (c) 2022-2025, NetApp, Inc
# GNU General Public License v3.0+  (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
module: na_ontap_file_security_permissions
short_description: NetApp ONTAP NTFS file security permissions
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap_rest
version_added: 22.0.0
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
  - Create, delete, or modify NTFS file security and audit policies of file or directory on NetApp ONTAP.
  - Note that ACLs are mached based on ('user', 'access', 'access_control', 'apply_to').
    In order to modify any of these 4 properties, the module deletes the ACL and creates a new one.

options:
  state:
    description:
      - Whether the specified file security permission should exist or not.
      - When absent, all ACLs are deleted, irrespective of the contents of C(acls).
      - See C(access_control) to only delete all SLAG ACLS, or only delete file-directory ACLs.
      - Inherited ACLs are ignored, they can't be deleted or modified.
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

  owner:
    description:
      - Specifies the owner of the NTFS security descriptor (SD).
      - You can specify the owner using either a user name or security identifier (SID).
      - The owner of the SD can modify the permissions on the file (or folder) or files (or folders) to which the SD is applied and
        can give other users the right to take ownership of the object or objects to which the SD is applied.
    type: str

  control_flags:
    description:
      - Specifies the control flags in the SD. It is a Hexadecimal Value.
    type: str

  group:
    description:
      - Specifies the owner's primary group.
      - Specify the owner group using either a group name or SID.
    type: str

  ignore_paths:
    description:
      - For each file or directory in the list, specifies that permissions on this file or directory cannot be replaced.
    type: list
    elements: str

  propagation_mode:
    description:
      - Specifies how to propagate security settings to child subfolders and files.
      - Defaults to propagate.
    choices: ['propagate', 'replace']
    type: str

  access_control:
    description:
      - An Access Control Level specifies the access control of the task to be applied.
      - Valid values are "file-directory" or "Storage-Level Access Guard (SLAG)".
      - SLAG is used to apply the specified security descriptors with the task for the volume or qtree.
      - Otherwise, the security descriptors are applied on files and directories at the specified path.
      - The value slag is not supported on FlexGroups volumes. The default value is "file-directory".
      - This field requires ONTAP 9.10.1 or later.  This defaults to "file_directory".
      - When state is present, all ACLs not listed in C(acls) are deleted when this option is absent.
        If this option is present, only ACLs matching its value are deleted.
      - When state is absent, all ACLs are deleted when this option is absent.
        If this option is present, only ACLs matching its value are deleted.
    choices: ['file_directory', 'slag']
    type: str

  acls:
    description:
      - A discretionary access security list (DACL) identifies the trustees that are allowed or denied access to a securable object.
      - When a process tries to access a securable object, the system checks the access control entries (ACEs)
        in the object's DACL to determine whether to grant access to it.
    type: list
    elements: dict
    suboptions:
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
          - Specifies whether the ACL is for DACL or SACL.
          - Currently tested with access_allow, access_deny for DACL and audit_failure, audit_success for SACL.
        choices: [access_allow, access_deny,
                  access_allowed_callback, access_denied_callback, access_allowed_callback_object, access_denied_callback_object,
                  system_audit_callback, system_audit_callback_object, system_resource_attribute, system_scoped_policy_id,
                  audit_failure, audit_success, audit_success_and_failure]
        type: str
        required: true
      user:
        description:
          - Specifies the account to which the ACE applies. Specify either name or SID.
          - As of 21.24.0, the module is not idempotent when using a SID.
          - To make it easier when also using C(na_ontap_file_security_permissions_acl), this is aliased to C(acl_user).
        type: str
        required: true
        aliases: ['acl_user']
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
          - At least one suboption must be set to true.  Suboptions that are not set are assumed to be false.
          - With SLAGs, ONTAP accepts the three suboptions to be set to true, but creates 2 ACLs.
            This module requires the 2 ACLs to be present to preserve idempotency.
            See also C(validate_changes).
        type: dict
        required: false
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
          delete:
            description:
              - Delete.
            type: bool
          delete_child:
            description:
              - Delete Child.
            type: bool
          execute_file:
            description:
              - Execute File.
            type: bool
          full_control:
            description:
              - Full Control.
            type: bool
          read_attr:
            description:
              - Read Attributes.
            type: bool
          read_data:
            description:
              - Read Data.
            type: bool
          read_ea:
            description:
              - Read Extended Attributes.
            type: bool
          read_perm:
            description:
              - Read Permissions.
            type: bool
          write_attr:
            description:
              - Write Attributes.
            type: bool
          write_data:
            description:
              - Write Data.
            type: bool
          write_ea:
            description:
              - Write Extended Attributes.
            type: bool
          write_owner:
            description:
              - Write Owner.
            type: bool
          write_perm:
            description:
              - Write Permission.
            type: bool
      ignore_paths:
        description:
          - For each file or directory in the list, specifies that permissions on this file or directory cannot be replaced.
        type: list
        elements: str
      propagation_mode:
        description:
          - Specifies how to propagate security settings to child subfolders and files.
          - Defaults to propagate.
          - This option valid only in create ACL.
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
  - Only supported with REST and requires ONTAP 9.9.1 or later..
  - SLAG requires ONTAP 9.10.1 or later.
  - When state is present, if an ACL is inherited, and a desired ACL matches, a new ACL is created as the inherited cannot be modified.
  - When state is absent, inherited ACLs are ignored.
'''

EXAMPLES = """
- name: Create file directory security permissions.
  netapp.ontap.na_ontap_file_security_permissions:
    state: present
    vserver: svm1
    access_control: file_directory
    path: /vol200/newfile.txt
    owner: "{{ user }}"
    # Note, wihout quotes, use a single backslash in AD user names
    # with quotes, it needs to be escaped as a double backslash
    # user: "ANSIBLE_CIFS\\user1"
    # we can't show an example with a single backslash as this is a python file, but it works in YAML.
    acls:
      - access: access_deny
        user: "{{ user }}"
        apply_to:
          files: true
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Modify file directory security permissions.
  netapp.ontap.na_ontap_file_security_permissions:
    state: present
    vserver: svm1
    access_control: file_directory
    path: /vol200/newfile.txt
    acls:
      - access: access_deny
        user: "{{ user }}"
        apply_to:
          files: true
      - access: access_allow
        user: "{{ user }}"
        apply_to:
          files: true
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Delete file directory security ACLs.
  netapp.ontap.na_ontap_file_security_permissions:
    state: absent
    vserver: svm1
    access_control: file_directory
    path: /vol200/newfile.txt
    acls:
      - access: access_deny
        user: "{{ user }}"
        apply_to:
          files: true
      - access: access_allow
        user: "{{ user }}"
        apply_to:
          files: true
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
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic, rest_vserver


class NetAppOntapFileSecurityPermissions:
    def __init__(self):
        self.argument_spec = netapp_utils.na_ontap_rest_only_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            vserver=dict(required=True, type='str'),
            path=dict(required=True, type='str'),
            owner=dict(required=False, type='str'),
            control_flags=dict(required=False, type='str'),
            group=dict(required=False, type='str'),
            access_control=dict(required=False, type='str', choices=['file_directory', 'slag']),
            ignore_paths=dict(required=False, type='list', elements='str'),
            propagation_mode=dict(required=False, type='str', choices=['propagate', 'replace']),
            acls=dict(type='list', elements='dict', options=dict(
                access=dict(required=True, type='str', choices=[
                    'access_allow', 'access_deny',
                    'access_allowed_callback', 'access_denied_callback', 'access_allowed_callback_object', 'access_denied_callback_object',
                    'system_audit_callback', 'system_audit_callback_object', 'system_resource_attribute', 'system_scoped_policy_id',
                    'audit_failure', 'audit_success', 'audit_success_and_failure']),
                access_control=dict(required=False, type='str', choices=['file_directory', 'slag']),
                user=dict(required=True, type='str', aliases=['acl_user']),
                rights=dict(required=False,
                            choices=['no_access', 'full_control', 'modify', 'read_and_execute', 'read', 'write'],
                            type='str'),
                apply_to=dict(required=False, type='dict', options=dict(
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
            )),
            validate_changes=dict(required=False, type='str', choices=['ignore', 'warn', 'error'], default='error'),
        ))
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )
        self.svm_uuid = None
        self.na_helper = NetAppModule(self)
        self.parameters = self.na_helper.check_and_set_parameters(self.module)
        self.rest_api = netapp_utils.OntapRestAPI(self.module)
        self.rest_api.fail_if_not_rest_minimum_version('na_ontap_file_security_permissions', 9, 9, 1)
        dummy, error = self.rest_api.is_rest(partially_supported_rest_properties=[['access_control', (9, 10, 1)], ['acls.access_control', (9, 10, 1)]],
                                             parameters=self.parameters)
        if error:
            self.module.fail_json(msg=error)
        self.parameters = self.na_helper.filter_out_none_entries(self.parameters)
        self.apply_to_keys = ['files', 'sub_folders', 'this_folder']
        # POST at SD level only expects a subset of keys in ACL
        self.post_acl_keys = ['access', 'advanced_rights', 'apply_to', 'rights', 'user']
        if self.parameters['state'] == 'present':
            self.validate_acls()

    def validate_acls(self):
        if 'acls' not in self.parameters:
            return
        self.parameters['acls'] = self.na_helper.filter_out_none_entries(self.parameters['acls'])
        for acl in self.parameters['acls']:
            if 'rights' in acl:
                if 'advanced_rights' in acl:
                    self.module.fail_json(msg="Error: suboptions 'rights' and 'advanced_rights' are mutually exclusive.")
                self.module.warn('This module is not idempotent when "rights" is used, make sure to use "advanced_rights".')
            # validate that at least one suboption is true
            if self.na_helper.safe_get(acl, ['apply_to']) is not None \
                    and not any(self.na_helper.safe_get(acl, ['apply_to', key]) for key in self.apply_to_keys):
                self.module.fail_json(msg="Error: at least one suboption must be true for apply_to.  Got: %s" % acl)
            # add default suboptions values if apply_to is not given
            if acl.get('apply_to') is None:
                apply_to = {'apply_to': {
                    'sub_folders': True,
                    'this_folder': True,
                    'files': True
                }
                }
                acl.update(apply_to)
            # error if identical acls are set.
            self.match_acl_with_acls(acl, self.parameters['acls'])
        for option in ('access_control', 'ignore_paths', 'propagation_mode'):
            value = self.parameters.get(option)
            if value is not None:
                for acl in self.parameters['acls']:
                    if acl.get(option) not in (None, value):
                        self.module.fail_json(msg="Error: mismatch between top level value and ACL value for %s: %s vs %s"
                                              % (option, value, acl.get(option)))
                    # make sure options are set in ach ACL, so we can match easily desired ACLs with current ACLs
                    acl[option] = value

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

    def get_file_security_permissions(self):
        api = 'protocols/file-security/permissions/%s/%s' % (self.svm_uuid, self.url_encode(self.parameters['path']))
        fields = 'acls,control_flags,group,owner'
        record, error = rest_generic.get_one_record(self.rest_api, api, {'fields': fields})
        # If we get 655865 the path we gave was not found, so we don't want to fail we want to return None
        if error:
            # if path not exists and state absent, return None and changed is False.
            if '655865' in error and self.parameters['state'] == 'absent':
                return None
            self.module.fail_json(msg="Error fetching file security permissions %s: %s" % (self.parameters['path'], to_native(error)),
                                  exception=traceback.format_exc())
        return self.form_current(record) if record else None

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

    @staticmethod
    def has_acls(current):
        return bool(current and current.get('acls'))

    def set_option(self, body, option):
        if self.parameters.get(option) is not None:
            body[option] = self.parameters[option]
            return True
        return False

    def sanitize_acl_for_post(self, acl):
        ''' some fields like access_control, propagation_mode are not accepted for POST operation '''
        post_acl = dict(acl)
        for key in acl:
            if key not in self.post_acl_keys:
                post_acl.pop(key)
        return post_acl

    def sanitize_acls_for_post(self, acls):
        ''' some fields like access_control, propagation_mode are not accepted for POST operation '''
        return [self.sanitize_acl_for_post(acl) for acl in acls]

    def create_file_security_permissions(self):
        api = 'protocols/file-security/permissions/%s/%s' % (self.svm_uuid, self.url_encode(self.parameters['path']))
        body = {}
        for option in ('access_control', 'control_flags', 'group', 'owner', 'ignore_paths', 'propagation_mode'):
            self.set_option(body, option)
        body['acls'] = self.sanitize_acls_for_post(self.parameters.get('acls', []))
        dummy, error = rest_generic.post_async(self.rest_api, api, body, job_timeout=120)
        if error:
            self.module.fail_json(msg='Error creating file security permissions %s: %s' % (self.parameters['path'], to_native(error)),
                                  exception=traceback.format_exc())

    def add_file_security_permissions_acl(self, acl):
        api = 'protocols/file-security/permissions/%s/%s/acl' % (self.svm_uuid, self.url_encode(self.parameters['path']))
        for option in ('access_control', 'propagation_mode'):
            # we already verified these options are consistent when present, so it's OK to overrid
            self.set_option(acl, option)
        dummy, error = rest_generic.post_async(self.rest_api, api, acl, timeout=0)
        if error:
            self.module.fail_json(msg='Error adding file security permissions acl %s: %s' % (self.parameters['path'], to_native(error)),
                                  exception=traceback.format_exc())

    def modify_file_security_permissions_acl(self, acl):
        api = 'protocols/file-security/permissions/%s/%s/acl' % (self.svm_uuid, self.url_encode(self.parameters['path']))
        acl = dict(acl)
        user = acl.pop('user')
        for option in ('access_control', 'propagation_mode'):
            # we already verified these options are consistent when present, so it's OK to overrid
            self.set_option(acl, option)
        dummy, error = rest_generic.patch_async(self.rest_api, api, self.url_encode(user), acl, {'return_records': 'true'})
        if error:
            self.module.fail_json(msg='Error modifying file security permissions acl %s: %s' % (self.parameters['path'], to_native(error)),
                                  exception=traceback.format_exc())

    def delete_file_security_permissions_acl(self, acl):
        api = 'protocols/file-security/permissions/%s/%s/acl' % (self.svm_uuid, self.url_encode(self.parameters['path']))
        # some fieds are set to None when not present
        acl = self.na_helper.filter_out_none_entries(acl)
        # drop keys not accepted in body
        user = acl.pop('user')
        acl.pop('advanced_rights', None)
        acl.pop('rights', None)
        acl.pop('inherited', None)
        for option in ('access_control', 'propagation_mode'):
            # we already verified these options are consistent when present, so it's OK to override
            self.set_option(acl, option)
        dummy, error = rest_generic.delete_async(self.rest_api, api, self.url_encode(user), {'return_records': 'true'}, acl, timeout=0)
        if error:
            self.module.fail_json(msg='Error deleting file security permissions acl %s: %s' % (self.parameters['path'], to_native(error)),
                                  exception=traceback.format_exc())

    def modify_file_security_permissions(self, modify):
        api = 'protocols/file-security/permissions/%s/%s' % (self.svm_uuid, self.url_encode(self.parameters['path']))
        body = {}
        for option in modify:
            self.set_option(body, option)
        dummy, error = rest_generic.patch_async(self.rest_api, api, None, body, job_timeout=120)
        if error:
            self.module.fail_json(msg='Error modifying file security permissions %s: %s' % (self.parameters['path'], to_native(error)),
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
                    and acl.get('apply_to') == an_acl.get('apply_to')
                    and not inherited):
                matches.append(an_acl)
        if len(matches) > 1:
            self.module.fail_json(msg='Error: found more than one desired ACLs with same user, access, access_control and apply_to  %s' % matches)
        return matches[0] if matches else None

    def get_acl_actions_on_modify(self, modify, current):
        acl_actions = {'patch-acls': [], 'post-acls': [], 'delete-acls': []}
        if not self.has_acls(current):
            acl_actions['post-acls'] = modify['acls']
            return acl_actions
        for acl in modify['acls']:
            current_acl = self.match_acl_with_acls(acl, current['acls'])
            if current_acl:
                # if exact match of 2 acl found, look for modify in that matched desired and current acl.
                if self.is_modify_acl_required(acl, current_acl):
                    acl_actions['patch-acls'].append(acl)
            else:
                acl_actions['post-acls'].append(acl)
        # Ignore inherited ACLs
        for acl in current['acls']:
            desired_acl = self.match_acl_with_acls(acl, self.parameters['acls'])
            if not desired_acl and not acl.get('inherited') and self.parameters.get('access_control') in (None, acl.get('access_control')):
                # only delete ACLs that matches the desired access_control, or all ACLs if not set
                acl_actions['delete-acls'].append(acl)
        return acl_actions

    def is_modify_acl_required(self, desired_acl, current_acl):
        current_acl_copy = current_acl.copy()
        current_acl_copy.pop('user')
        modify = self.na_helper.get_modified_attributes(current_acl_copy, desired_acl)
        return bool(modify)

    def get_acl_actions_on_delete(self, current):
        acl_actions = {'patch-acls': [], 'post-acls': [], 'delete-acls': []}
        self.na_helper.changed = False
        if current.get('acls'):
            for acl in current['acls']:
                # only delete ACLs that matches the desired access_control, or all ACLs if not set
                if not acl.get('inherited') and self.parameters.get('access_control') in (None, acl.get('access_control')):
                    self.na_helper.changed = True
                    acl_actions['delete-acls'].append(acl)
        return acl_actions

    def get_modify_actions(self, current):
        modify = self.na_helper.get_modified_attributes(current, self.parameters)
        if 'path' in modify:
            self.module.fail_json(msg='Error: mismatch on path values: desired: %s, received: %s' % (self.parameters['path'], current['path']))
        if 'acls' in modify:
            acl_actions = self.get_acl_actions_on_modify(modify, current)
            # validate_modify function will check a modify in acl is required or not.
            # if neither patch-acls or post-acls required and modify None, set changed to False.
            del modify['acls']
        else:
            acl_actions = {'patch-acls': [], 'post-acls': [], 'delete-acls': []}
        if not any((acl_actions['patch-acls'], acl_actions['post-acls'], acl_actions['delete-acls'], modify)):
            self.na_helper.changed = False
        return modify, acl_actions

    def get_acl_actions_on_create(self):
        """
        POST does not accept access_control and propagation_mode at the ACL level, these are global values for all ACLs.
        Since the user could have a list of ACLs with mixed property we should useP OST the create the SD and 1 group of ACLs
        then loop over the remaining ACLS.
        """
        # split ACLs into four categories
        acls_groups = {}
        preferred_group = (None, None)
        special_accesses = []
        for acl in self.parameters.get('acls', []):
            access_control = acl.get('access_control', 'file_directory')
            propagation_mode = acl.get('propagation_mode', 'propagate')
            if access_control not in acls_groups:
                acls_groups[access_control] = {}
            if propagation_mode not in acls_groups[access_control]:
                acls_groups[access_control][propagation_mode] = []
            acls_groups[access_control][propagation_mode].append(acl)
            access = acl.get('access')
            if access not in ('access_allow', 'access_deny', 'audit_success', 'audit_failure'):
                if preferred_group == (None, None):
                    preferred_group = (access_control, propagation_mode)
                if preferred_group != (access_control, propagation_mode):
                    self.module.fail_json(msg="Error: acl %s with access %s conflicts with other ACLs using accesses: %s "
                                              "with different access_control or propagation_mode: %s."
                                          % (acl, access, special_accesses, preferred_group))
                special_accesses.append(access)

        if preferred_group == (None, None):
            # find a non empty list of ACLs
            # use sorted to make this deterministic
            for acc_key, acc_value in sorted(acls_groups.items()):
                for prop_key, prop_value in sorted(acc_value.items()):
                    if prop_value:
                        preferred_group = (acc_key, prop_key)
                        break
                if preferred_group != (None, None):
                    break

        # keep one category for create, and move the remaining ACLs into post-acls
        create_acls = []
        acl_actions = {'patch-acls': [], 'post-acls': [], 'delete-acls': []}
        # use sorted to make this deterministic
        for acc_key, acc_value in sorted(acls_groups.items()):
            for prop_key, prop_value in sorted(acc_value.items()):
                if (acc_key, prop_key) == preferred_group:
                    create_acls = prop_value
                    self.parameters['access_control'] = acc_key
                    self.parameters['propagation_mode'] = prop_key
                elif prop_value:
                    acl_actions['post-acls'].extend(prop_value)
        self.parameters['acls'] = create_acls
        return acl_actions

    def get_actions(self):
        current = self.get_file_security_permissions()
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        modify, acl_actions = self.get_modify_actions(current) if cd_action is None else (None, {})
        if cd_action == 'create' and self.parameters.get('access_control') is None:
            acl_actions = self.get_acl_actions_on_create()
        if cd_action == 'delete':
            # delete is not supported by the API, or rather a DELETE will only delete the SLAG ACLs and nothing else.
            # so we just loop through all the ACLs
            acl_actions = self.get_acl_actions_on_delete(current)
            cd_action = None
        return cd_action, modify, acl_actions

    def apply(self):

        self.get_svm_uuid()
        cd_action, modify, acl_actions = self.get_actions()
        if self.na_helper.changed and not self.module.check_mode:
            if cd_action == 'create':
                self.create_file_security_permissions()
            if modify:
                self.modify_file_security_permissions(modify)
            # delete ACLs first, to avoid conflicts with new or modified rules
            for delete_acl in acl_actions.get('delete-acls', []):
                self.delete_file_security_permissions_acl(delete_acl)
            # PATCH call succeeds, but its not working: changes are not reflecting
            # modify before adding new rules to avoid conflicts
            for patch_acl in acl_actions.get('patch-acls', []):
                self.modify_file_security_permissions_acl(patch_acl)
            for post_acl in acl_actions.get('post-acls', []):
                self.add_file_security_permissions_acl(post_acl)
            changed = self.na_helper.changed
            self.validate_changes(cd_action, modify)
            self.na_helper.changed = changed
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action, modify)
        self.module.exit_json(**result)

    def validate_changes(self, cd_action, modify):
        if self.parameters['validate_changes'] == 'ignore':
            return
        new_cd_action, new_modify, acl_actions = self.get_actions()
        errors = []
        if new_cd_action is not None:
            errors.append('%s still required after %s (with modify: %s)' % (new_cd_action, cd_action, modify))
        if new_modify:
            errors.append('modify: %s still required after %s' % (new_modify, modify))
        # changes in ACLs
        errors.extend('%s still required for %s' % (key, value) for key, value in acl_actions.items() if value)
        if errors:
            msg = 'Error - %s' % ' - '.join(errors)
            if self.parameters['validate_changes'] == 'error':
                self.module.fail_json(msg=msg)
            if self.parameters['validate_changes'] == 'warn':
                self.module.warn(msg)


def main():
    """Apply volume operations from playbook"""
    obj = NetAppOntapFileSecurityPermissions()
    obj.apply()


if __name__ == '__main__':
    main()
