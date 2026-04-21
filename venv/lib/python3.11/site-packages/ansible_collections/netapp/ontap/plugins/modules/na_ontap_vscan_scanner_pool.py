#!/usr/bin/python

# (c) 2018-2024, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

'''
na_ontap_vscan_scanner_pool
'''

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
module: na_ontap_vscan_scanner_pool
short_description: NetApp ONTAP Vscan Scanner Pools Configuration.
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap
version_added: 2.8.0
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
- Create/Modify/Delete a Vscan Scanner Pool
options:
  state:
    description:
    - Whether a Vscan Scanner pool is present or not
    choices: ['present', 'absent']
    type: str
    default: present

  vserver:
    description:
    - the name of the data vserver to use.
    required: true
    type: str

  hostnames:
    description:
    - List of hostnames of Vscan servers which are allowed to connect to Data ONTAP
    type: list
    elements: str

  privileged_users:
    description:
    - List of privileged usernames. Username must be in the form "domain-name\\user-name"
    type: list
    elements: str

  scanner_pool:
    description:
    - the name of the virus scanner pool
    required: true
    type: str

  scanner_policy:
    description:
    - The name of the Virus scanner Policy
    choices: ['primary', 'secondary', 'idle']
    type: str
'''

EXAMPLES = """
- name: Create and enable Scanner pool
  netapp.ontap.na_ontap_vscan_scanner_pool:
    state: present
    username: '{{ netapp_username }}'
    password: '{{ netapp_password }}'
    hostname: '{{ netapp_hostname }}'
    vserver: carchi-vsim2
    hostnames: ['name', 'name2']
    privileged_users: ['sim.rtp.openeng.netapp.com\\admin', 'sim.rtp.openeng.netapp.com\\carchi']
    scanner_pool: Scanner1
    scanner_policy: primary

- name: Modify scanner pool
  netapp.ontap.na_ontap_vscan_scanner_pool:
    state: present
    username: '{{ netapp_username }}'
    password: '{{ netapp_password }}'
    hostname: '{{ netapp_hostname }}'
    vserver: carchi-vsim2
    hostnames: ['name', 'name2', 'name3']
    privileged_users: ['sim.rtp.openeng.netapp.com\\admin', 'sim.rtp.openeng.netapp.com\\carchi', 'sim.rtp.openeng.netapp.com\\chuyic']
    scanner_pool: Scanner1

- name: Delete a scanner pool
  netapp.ontap.na_ontap_vscan_scanner_pool:
    state: absent
    username: '{{ netapp_username }}'
    password: '{{ netapp_password }}'
    hostname: '{{ netapp_hostname }}'
    vserver: carchi-vsim2
    scanner_pool: Scanner1
"""

RETURN = """

"""

import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp import OntapRestAPI
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic
from ansible_collections.netapp.ontap.plugins.module_utils import rest_vserver

HAS_NETAPP_LIB = netapp_utils.has_netapp_lib()


class NetAppOntapVscanScannerPool(object):
    ''' create, modify, delete vscan scanner pool '''
    def __init__(self):
        self.use_rest = False
        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            vserver=dict(required=True, type='str'),
            hostnames=dict(required=False, type='list', elements='str'),
            privileged_users=dict(required=False, type='list', elements='str'),
            scanner_pool=dict(required=True, type='str'),
            scanner_policy=dict(required=False, type='str', choices=['primary', 'secondary', 'idle'])
        ))
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )
        self.svm_uuid = None
        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)

        self.rest_api = OntapRestAPI(self.module)
        self.use_rest = self.rest_api.is_rest()
        if self.use_rest and not self.rest_api.meets_rest_minimum_version(self.use_rest, 9, 6):
            msg = 'REST requires ONTAP 9.6 or later for /protocols/vscan/{{svm.uuid}}/scanner-pools APIs'
            self.use_rest = self.na_helper.fall_back_to_zapi(self.module, msg, self.parameters)
        if not self.use_rest:
            if HAS_NETAPP_LIB is False:
                self.module.fail_json(msg=netapp_utils.netapp_lib_is_required())
            self.server = netapp_utils.setup_na_ontap_zapi(module=self.module, vserver=self.parameters['vserver'])

    def create_scanner_pool(self):
        """
        Create a Vscan Scanner Pool
        :return: nothing
        """
        if self.use_rest:
            return self.create_scanner_pool_rest()
        scanner_pool_obj = netapp_utils.zapi.NaElement('vscan-scanner-pool-create')
        if self.parameters['hostnames']:
            string_obj = netapp_utils.zapi.NaElement('hostnames')
            scanner_pool_obj.add_child_elem(string_obj)
            for hostname in self.parameters['hostnames']:
                string_obj.add_new_child('string', hostname)
        if self.parameters['privileged_users']:
            users_obj = netapp_utils.zapi.NaElement('privileged-users')
            scanner_pool_obj.add_child_elem(users_obj)
            for user in self.parameters['privileged_users']:
                users_obj.add_new_child('privileged-user', user)
        scanner_pool_obj.add_new_child('scanner-pool', self.parameters['scanner_pool'])
        try:
            self.server.invoke_successfully(scanner_pool_obj, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error creating Vscan Scanner Pool %s: %s' %
                                  (self.parameters['scanner_policy'], to_native(error)),
                                  exception=traceback.format_exc())

    def apply_policy(self):
        """
        Apply a Scanner policy to a Scanner pool
        :return: nothing
        """
        apply_policy_obj = netapp_utils.zapi.NaElement('vscan-scanner-pool-apply-policy')
        apply_policy_obj.add_new_child('scanner-policy', self.parameters['scanner_policy'])
        apply_policy_obj.add_new_child('scanner-pool', self.parameters['scanner_pool'])
        try:
            self.server.invoke_successfully(apply_policy_obj, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error appling policy %s to pool %s: %s' %
                                  (self.parameters['scanner_policy'], self.parameters['scanner_policy'], to_native(error)),
                                  exception=traceback.format_exc())

    def get_scanner_pool(self):
        """
        Check to see if a scanner pool exist or not
        :return: True if it exist, False if it does not
        """
        if self.use_rest:
            return self.get_scanner_pool_rest()
        return_value = None
        scanner_pool_obj = netapp_utils.zapi.NaElement('vscan-scanner-pool-get-iter')
        scanner_pool_info = netapp_utils.zapi.NaElement('vscan-scanner-pool-info')
        scanner_pool_info.add_new_child('scanner-pool', self.parameters['scanner_pool'])
        scanner_pool_info.add_new_child('vserver', self.parameters['vserver'])
        query = netapp_utils.zapi.NaElement('query')
        query.add_child_elem(scanner_pool_info)
        scanner_pool_obj.add_child_elem(query)
        try:
            result = self.server.invoke_successfully(scanner_pool_obj, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error searching for Vscan Scanner Pool %s: %s' %
                                  (self.parameters['scanner_pool'], to_native(error)), exception=traceback.format_exc())
        if result.get_child_by_name('num-records') and int(result.get_child_content('num-records')) >= 1:
            if result.get_child_by_name('attributes-list').get_child_by_name('vscan-scanner-pool-info').get_child_content(
                    'scanner-pool') == self.parameters['scanner_pool']:
                scanner_pool_obj = result.get_child_by_name('attributes-list').get_child_by_name('vscan-scanner-pool-info')
                hostname = [host.get_content() for host in
                            scanner_pool_obj.get_child_by_name('hostnames').get_children()]
                privileged_users = [user.get_content() for user in
                                    scanner_pool_obj.get_child_by_name('privileged-users').get_children()]
                return_value = {
                    'hostnames': hostname,
                    'enable': scanner_pool_obj.get_child_content('is-currently-active'),
                    'privileged_users': privileged_users,
                    'scanner_pool': scanner_pool_obj.get_child_content('scanner-pool'),
                    'scanner_policy': scanner_pool_obj.get_child_content('scanner-policy')
                }
        return return_value

    def delete_scanner_pool(self):
        """
        Delete a Scanner pool
        :return: nothing
        """
        if self.use_rest:
            return self.delete_scanner_pool_rest()
        scanner_pool_obj = netapp_utils.zapi.NaElement('vscan-scanner-pool-delete')
        scanner_pool_obj.add_new_child('scanner-pool', self.parameters['scanner_pool'])
        try:
            self.server.invoke_successfully(scanner_pool_obj, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error deleting Vscan Scanner Pool %s: %s' %
                                  (self.parameters['scanner_pool'], to_native(error)),
                                  exception=traceback.format_exc())

    def modify_scanner_pool(self, modify):
        """
        Modify a scanner pool
        :return: nothing
        """
        if self.use_rest:
            return self.modify_scanner_pool_rest(modify)
        vscan_pool_modify = netapp_utils.zapi.NaElement('vscan-scanner-pool-modify')
        vscan_pool_modify.add_new_child('scanner-pool', self.parameters['scanner_pool'])
        for key in modify:
            if key == 'privileged_users':
                users_obj = netapp_utils.zapi.NaElement('privileged-users')
                vscan_pool_modify.add_child_elem(users_obj)
                for user in modify['privileged_users']:
                    users_obj.add_new_child('privileged-user', user)
            elif key == 'hostnames':
                string_obj = netapp_utils.zapi.NaElement('hostnames')
                vscan_pool_modify.add_child_elem(string_obj)
                for hostname in modify['hostnames']:
                    string_obj.add_new_child('string', hostname)
            elif key != 'scanner_policy':
                vscan_pool_modify.add_new_child(self.attribute_to_name(key), str(modify[key]))

        try:
            self.server.invoke_successfully(vscan_pool_modify, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error modifying Vscan Scanner Pool %s: %s' %
                                  (self.parameters['scanner_pool'], to_native(error)),
                                  exception=traceback.format_exc())

    @staticmethod
    def attribute_to_name(attribute):
        return str.replace(attribute, '_', '-')

    def get_svm_uuid(self):
        """
        Get a vserver's uuid
        :return: nothing
        """
        record, error = rest_vserver.get_vserver_uuid(self.rest_api, self.parameters['vserver'])
        if error is not None:
            self.module.fail_json(msg="Error fetching vserver %s: %s" % (self.parameters['vserver'], to_native(error)),
                                  exception=traceback.format_exc())
        if record is None:
            self.module.fail_json(msg="Error fetching vserver %s. Please make sure vserver name is correct."
                                  % self.parameters['vserver'], exception=traceback.format_exc())
        self.svm_uuid = record

    def get_scanner_pool_rest(self):
        """
        Check to see if a scanner pool exist or not using REST
        :return: record if it exist, None if it does not
        """
        self.get_svm_uuid()
        api = 'protocols/vscan/%s/scanner-pools' % self.svm_uuid
        query = {'name': self.parameters.get('scanner_pool'),
                 'fields': 'servers,'
                           'privileged_users,'}
        if self.parameters.get('scanner_policy') is not None:
            query['fields'] += 'role,'

        record, error = rest_generic.get_one_record(self.rest_api, api, query)
        if error:
            self.module.fail_json(msg='Error searching for Vscan Scanner Pool %s: %s' %
                                  (self.parameters['scanner_pool'], to_native(error)),
                                  exception=traceback.format_exc())
        if record:
            return {
                'scanner_pool': record.get('name'),
                'hostnames': record.get('servers'),
                'privileged_users': record.get('privileged_users'),
                'scanner_policy': record.get('role'),
            }
        return None

    def create_scanner_pool_rest(self):
        """
        Create a Vscan Scanner Pool using REST
        :return: nothing
        """
        api = 'protocols/vscan/%s/scanner-pools' % self.svm_uuid
        body = {
            'name': self.parameters['scanner_pool'],
            'servers': self.parameters['hostnames'],
            'privileged_users': self.parameters['privileged_users'],
        }
        if 'scanner_policy' in self.parameters:
            body['role'] = self.parameters['scanner_policy']

        dummy, error = rest_generic.post_async(self.rest_api, api, body)
        if error is not None:
            self.module.fail_json(msg='Error creating Vscan Scanner Pool %s: %s' %
                                  (self.parameters['scanner_pool'], to_native(error)),
                                  exception=traceback.format_exc())

    def delete_scanner_pool_rest(self):
        """
        Delete a Scanner pool using REST
        :return: nothing
        """
        api = 'protocols/vscan/%s/scanner-pools/%s' % (self.svm_uuid, self.parameters['scanner_pool'])
        dummy, error = rest_generic.delete_async(self.rest_api, api, uuid=None)
        if error is not None:
            self.module.fail_json(msg='Error deleting Vscan Scanner Pool %s: %s' %
                                  (self.parameters['scanner_pool'], to_native(error)),
                                  exception=traceback.format_exc())

    def modify_scanner_pool_rest(self, modify):
        """
        Modify a scanner pool using REST
        :return: nothing
        """
        api = 'protocols/vscan/%s/scanner-pools/%s' % (self.svm_uuid, self.parameters['scanner_pool'])
        body = {}
        for key, option in [
            ('servers', 'hostnames'),
            ('privileged_users', 'privileged_users'),
            ('role', 'scanner_policy'),
        ]:
            if modify.get(option) is not None:
                body[key] = modify[option]

        dummy, error = rest_generic.patch_async(self.rest_api, api, uuid_or_name=None, body=body)
        if error:
            self.module.fail_json(msg='Error modifying Vscan Scanner Pool %s: %s.' %
                                  (self.parameters['scanner_pool'], to_native(error)),
                                  exception=traceback.format_exc())

    def apply(self):
        current = self.get_scanner_pool()
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        modify = None
        if self.parameters['state'] == 'present' and cd_action is None:
            modify = self.na_helper.get_modified_attributes(current, self.parameters)
        if self.na_helper.changed and not self.module.check_mode:
            if cd_action == 'create':
                self.create_scanner_pool()
                if not self.use_rest and self.parameters.get('scanner_policy') is not None:
                    self.apply_policy()
            elif cd_action == 'delete':
                self.delete_scanner_pool()
            elif modify:
                self.modify_scanner_pool(modify)
                if not self.use_rest and self.parameters.get('scanner_policy') is not None:
                    self.apply_policy()
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action, modify)
        self.module.exit_json(**result)


def main():
    """
    Execute action from playbook
    """
    scanner_pool = NetAppOntapVscanScannerPool()
    scanner_pool.apply()


if __name__ == '__main__':
    main()
