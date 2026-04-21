#!/usr/bin/python

# (c) 2022-2025, NetApp, Inc
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function
__metaclass__ = type

'''
na_ontap_name_mappings
'''


DOCUMENTATION = '''
module: na_ontap_name_mappings
short_description: NetApp ONTAP name mappings
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap_rest
version_added: 22.0.0
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
  - Create/Delete/Modify name mappings for an SVM on ONTAP.
options:
  state:
    description:
      - Whether the specified name mappings should exist or not.
    choices: ['present', 'absent']
    type: str
    default: present
  vserver:
    description:
      - Name of the vserver to use.
    required: true
    type: str
  client_match:
    description:
      - Client workstation IP Address which is matched when searching for the pattern.
      - Example '10.254.101.111/28'
      - Client match value can be in any of the following formats,
          - As an IPv4 address with a subnet mask expressed as a number of bits; for instance, 10.1.12.0/24
          - As an IPv6 address with a subnet mask expressed as a number of bits; for instance, fd20:8b1e:b255:4071::/64
          - As an IPv4 address with a network mask; for instance, 10.1.16.0/255.255.255.0
          - As a hostname
    type: str
  direction:
    description:
      - Direction in which the name mapping is applied.
      - The possible values are,
          krb_unix - Kerberos principal name to UNIX user name
          win_unix - Windows user name to UNIX user name
          unix_win - UNIX user name to Windows user name mapping
          s3_unix - S3 user name to UNIX user name mapping
          s3_win - S3 user name to Windows user name mapping
      - s3_unix and s3_win requires ONTAP 9.12.1 or later.
    choices: ['krb_unix', 'win_unix', 'unix_win', 's3_unix', 's3_win']
    required: true
    type: str
  index:
    description:
      - Position in the list of name mappings.
      - Minimum value is 1 and maximum is 2147483647.
    required: true
    type: int
  pattern:
    description:
      - Pattern used to match the name while searching for a name that can be used as a replacement.
      - The pattern is a UNIX-style regular expression.
      - Regular expressions are case-insensitive when mapping from Windows to UNIX,
        and they are case-sensitive for mappings from Kerberos to UNIX and UNIX to Windows.
      - Minimum length is 1 and maximum length is 256.
      - Pattern should be unique for each index of vserver.
      - Example ENGCIFS_AD_USER.
    type: str
  replacement:
    description:
      - The name that is used as a replacement, if the pattern associated with this entry matches.
      - Minimum length is 1 and maximum length is 256.
      - Example unix_user1.
    type: str
  from_index:
    description:
      - If no entry with index is found, it is created by reindexing the entry for from_index.
      - If no entry is found for index and from_index, an error is reported.
      - Minimum value is 1 and maximum is 2147483647.
      - Requires ONTAP version 9.7 or later.
    type: int

'''

EXAMPLES = '''
- name: Create name mappings configuration
  netapp.ontap.na_ontap_name_mappings:
    vserver: vserverName
    direction: win_unix
    index: 1
    pattern: ENGCIFS_AD_USER
    replacement: unix_user
    client_match: 10.254.101.111/28
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Modify name mappings configuration
  netapp.ontap.na_ontap_name_mappings:
    vserver: vserverName
    direction: win_unix
    index: 1
    pattern: ENGCIFS_AD_USERS
    replacement: unix_user1
    client_match: 10.254.101.112/28
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Swap name mappings position
  netapp.ontap.na_ontap_name_mappings:
    vserver: vserverName
    direction: win_unix
    index: 1
    pattern: ENGCIFS_AD_USERS
    replacement: unix_user1
    from_index: 2
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Delete name mappings configuration
  netapp.ontap.na_ontap_name_mappings:
    vserver: vserverName
    direction: win_unix
    index: 1
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
'''

RETURN = """
"""

from ansible.module_utils.basic import AnsibleModule
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic


class NetAppOntapNameMappings:
    """ object initialize and class methods """
    def __init__(self):
        self.argument_spec = netapp_utils.na_ontap_rest_only_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            vserver=dict(required=True, type='str'),
            client_match=dict(required=False, type='str'),
            direction=dict(required=True, type='str', choices=['krb_unix', 'win_unix', 'unix_win', 's3_unix', 's3_win']),
            index=dict(required=True, type='int'),
            from_index=dict(required=False, type='int'),
            pattern=dict(required=False, type='str'),
            replacement=dict(required=False, type='str'),
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )
        self.na_helper = NetAppModule(self)
        self.parameters = self.na_helper.set_parameters(self.module.params)
        self.svm_uuid = None
        self.rest_api = netapp_utils.OntapRestAPI(self.module)
        self.rest_api.fail_if_not_rest_minimum_version('na_ontap_name_mappings', 9, 6)
        self.rest_api.is_rest_supported_properties(self.parameters, None, [['from_index', (9, 7)]])
        if self.parameters['direction'] in ['s3_unix', 's3_win'] and not self.rest_api.meets_rest_minimum_version(True, 9, 12, 1):
            self.module.fail_json(msg="Error: direction %s requires ONTAP 9.12.1 or later version." % self.parameters['direction'])

    def get_name_mappings_rest(self, index=None):
        '''
        Retrieves the name mapping configuration for SVM with rest API.
        '''
        if index is None:
            index = self.parameters['index']
        query = {'svm.name': self.parameters.get('vserver'),
                 'index': index,  # the existing current index or from_index to be swapped
                 'direction': self.parameters.get('direction'),   # different directions can have same index
                 'fields': 'svm.uuid,'
                           'client_match,'
                           'direction,'
                           'index,'
                           'pattern,'
                           'replacement,'}
        api = 'name-services/name-mappings'
        record, error = rest_generic.get_one_record(self.rest_api, api, query)
        if error:
            self.module.fail_json(msg=error)
        if record:
            self.svm_uuid = record['svm']['uuid']
            return {
                'pattern': self.na_helper.safe_get(record, ['pattern']),
                'direction': self.na_helper.safe_get(record, ['direction']),
                'replacement': self.na_helper.safe_get(record, ['replacement']),
                'client_match': record.get('client_match', None),
            }
        return None

    def create_name_mappings_rest(self):
        """
        Creates name mappings for an SVM with REST API.
        """
        body = {'svm.name': self.parameters.get('vserver'),
                'index': self.parameters.get('index'),
                'direction': self.parameters.get('direction'),
                'pattern': self.parameters.get('pattern'),
                'replacement': self.parameters.get('replacement')}
        if 'client_match' in self.parameters:
            body['client_match'] = self.parameters['client_match']
        api = 'name-services/name-mappings'
        dummy, error = rest_generic.post_async(self.rest_api, api, body)
        if error is not None:
            self.module.fail_json(msg="Error on creating name mappings rest: %s" % error)

    def modify_name_mappings_rest(self, modify=None, reindex=False):
        """
        Updates the name mapping configuration of an SVM with rest API.
        Swap the position with new position(new_index).
        """
        body = {}
        query = None
        if modify:
            for option in ['pattern', 'replacement', 'client_match']:
                if option in modify:
                    body[option] = self.parameters[option]
        # Cannot swap entries which have hostname or address configured.
        # Delete and recreate the new entry at the specified position.
        index = self.parameters['index']
        if reindex:
            query = {'new_index': self.parameters.get('index')}
            index = self.parameters['from_index']

        api = 'name-services/name-mappings/%s/%s/%s' % (self.svm_uuid, self.parameters['direction'], index)
        dummy, error = rest_generic.patch_async(self.rest_api, api, None, body, query)
        if error is not None:
            self.module.fail_json(msg="Error on modifying name mappings rest: %s" % error)

    def delete_name_mappings_rest(self):
        """
        Delete the name mapping configuration of an SVM with rest API.
        """
        api = 'name-services/name-mappings/%s/%s/%s' % (self.svm_uuid, self.parameters['direction'], self.parameters['index'])
        dummy, error = rest_generic.delete_async(self.rest_api, api, None)
        if error is not None:
            self.module.fail_json(msg="Error on deleting name mappings rest: %s" % error)

    def apply(self):
        reindex = False
        current = self.get_name_mappings_rest()
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        # Throws error when trying to swap with non existing index
        if cd_action == 'create':
            if self.parameters.get('from_index') is not None:
                current = self.get_name_mappings_rest(self.parameters['from_index'])
                if not current:
                    self.module.fail_json(msg="Error from_index entry does not exist")
                reindex = True
                cd_action = None
            else:
                # pattern and replacement are required when creating name mappings.
                if not self.parameters.get('pattern') or not self.parameters.get('replacement'):
                    self.module.fail_json(msg="Error creating name mappings for an SVM, pattern and replacement are required in create.")
        modify = self.na_helper.get_modified_attributes(current, self.parameters) if cd_action is None else None

        if self.na_helper.changed and not self.module.check_mode:
            if cd_action == 'create':
                self.create_name_mappings_rest()
            elif cd_action == 'delete':
                self.delete_name_mappings_rest()
            elif modify or reindex:
                self.modify_name_mappings_rest(modify, reindex)
                if reindex:
                    modify['new_index'] = self.parameters.get('index')
                    modify['from_index'] = self.parameters['from_index']
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action, modify)
        self.module.exit_json(**result)


def main():
    """ Create object and call apply """
    mapping_obj = NetAppOntapNameMappings()
    mapping_obj.apply()


if __name__ == '__main__':
    main()
