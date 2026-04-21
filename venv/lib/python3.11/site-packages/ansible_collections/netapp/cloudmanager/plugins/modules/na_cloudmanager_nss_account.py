#!/usr/bin/python

# (c) 2021, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

'''
na_cloudmanager_nss_account
'''

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = '''

module: na_cloudmanager_nss_account
short_description: NetApp Cloud Manager nss account
extends_documentation_fragment:
    - netapp.cloudmanager.netapp.cloudmanager
version_added: '21.3.0'
author: NetApp Ansible Team (@carchi8py) <ng-ansibleteam@netapp.com>

description:
- Create and Delete nss account.

options:
    state:
        description:
        - Whether the specified nss account should exist or not.
        choices: ['present', 'absent']
        default: 'present'
        type: str

    client_id:
        description:
        - The connector ID of the Cloud Manager Connector.
        required: true
        type: str

    public_id:
        description:
        - The ID of the NSS account.
        type: str

    name:
        description:
        - The name of the NSS account.
        type: str

    username:
        description:
        - The NSS username.
        required: true
        type: str

    password:
        description:
        - The NSS password.
        type: str

    vsa_list:
        description:
        - The working environment list.
        type: list
        elements: str

notes:
- Support check_mode.
'''

EXAMPLES = '''
- name: Create nss account
  netapp.cloudmanager.na_cloudmanager_nss_account:
    state: present
    name: test_cloud
    username: test_cloud
    password: password
    client_id: your_client_id
    refresh_token: your_refresh_token
'''

RETURN = r''' # '''

from ansible.module_utils.basic import AnsibleModule
import ansible_collections.netapp.cloudmanager.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.cloudmanager.plugins.module_utils.netapp_module import NetAppModule


class NetAppCloudmanagerNssAccount(object):

    def __init__(self):
        """
        Parse arguments, setup state variables,
        check parameters and ensure request module is installed
        """
        self.argument_spec = netapp_utils.cloudmanager_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, choices=['present', 'absent'], default='present'),
            name=dict(required=False, type='str'),
            client_id=dict(required=True, type='str'),
            username=dict(required=True, type='str'),
            password=dict(required=False, type='str', no_log=True),
            public_id=dict(required=False, type='str'),
            vsa_list=dict(required=False, type='list', elements='str')
        ))
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            required_one_of=[['refresh_token', 'sa_client_id']],
            required_together=[['sa_client_id', 'sa_secret_key']],
            required_if=[
                ('state', 'present', ['password']),
            ],
            supports_check_mode=True
        )
        self.na_helper = NetAppModule()
        # set up state variables
        self.parameters = self.na_helper.set_parameters(self.module.params)
        # Calling generic rest_api class
        self.rest_api = netapp_utils.CloudManagerRestAPI(self.module)
        self.rest_api.token_type, self.rest_api.token = self.rest_api.get_token()
        self.rest_api.url += self.rest_api.environment_data['CLOUD_MANAGER_HOST']
        self.rest_api.api_root_path = '/occm/api/'
        self.headers = {
            'X-Agent-Id': self.rest_api.format_client_id(self.parameters['client_id'])
        }

    def get_nss_account(self):
        response, err, dummy = self.rest_api.send_request("GET", "%s/accounts" % (
            self.rest_api.api_root_path), None, header=self.headers)
        if err is not None:
            self.module.fail_json(changed=False, msg="Error: unexpected response on getting nss account: %s, %s" % (str(err), str(response)))
        if response is None:
            return None
        nss_accounts = []
        if response.get('nssAccounts'):
            nss_accounts = response['nssAccounts']
        if len(nss_accounts) == 0:
            return None
        result = dict()
        for account in nss_accounts:
            if account['nssUserName'] == self.parameters['username']:
                if self.parameters.get('public_id') and self.parameters['public_id'] != account['publicId']:
                    self.module.fail_json(changed=False, msg="Error: public_id '%s' does not match username."
                                                             % account['publicId'])
                else:
                    self.parameters['public_id'] = account['publicId']
                result['name'] = account['accountName']
                result['user_name'] = account['nssUserName']
                result['vsa_list'] = account['vsaList']
                return result
        return None

    def create_nss_account(self):
        account = dict()
        if self.parameters.get('name'):
            account['accountName'] = self.parameters['name']
        account['providerKeys'] = {'nssUserName': self.parameters['username'],
                                   'nssPassword': self.parameters['password']}
        account['vsaList'] = []
        if self.parameters.get('vsa_list'):
            account['vsaList'] = self.parameters['vsa_list']
        response, err, second_dummy = self.rest_api.send_request("POST", "%s/accounts/nss" % (
            self.rest_api.api_root_path), None, account, header=self.headers)
        if err is not None:
            self.module.fail_json(changed=False, msg="Error: unexpected response on creating nss account: %s, %s" % (str(err), str(response)))

    def delete_nss_account(self):
        response, err, second_dummy = self.rest_api.send_request("DELETE", "%s/accounts/%s" % (
            self.rest_api.api_root_path, self.parameters['public_id']), None, None, header=self.headers)
        if err is not None:
            self.module.fail_json(changed=False, msg="Error: unexpected response on deleting nss account: %s, %s" % (str(err), str(response)))
        return None

    def apply(self):
        current = self.get_nss_account()
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        if self.na_helper.changed and not self.module.check_mode:
            if cd_action == 'create':
                self.create_nss_account()
            elif cd_action == 'delete':
                self.delete_nss_account()
        self.module.exit_json(changed=self.na_helper.changed)


def main():
    '''Main Function'''
    account = NetAppCloudmanagerNssAccount()
    account.apply()


if __name__ == '__main__':
    main()
