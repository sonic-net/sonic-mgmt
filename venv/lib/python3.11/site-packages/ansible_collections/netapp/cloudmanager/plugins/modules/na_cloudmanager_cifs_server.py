#!/usr/bin/python

# (c) 2021, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

'''
na_cloudmanager_cifs_server
'''

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = '''

module: na_cloudmanager_cifs_server
short_description: NetApp Cloud Manager cifs server
extends_documentation_fragment:
    - netapp.cloudmanager.netapp.cloudmanager
version_added: '21.3.0'
author: NetApp Ansible Team (@carchi8py) <ng-ansibleteam@netapp.com>

description:
- Create or Delete a CIFS server on the Cloud Volume ONTAP system to support CIFS volumes, based on an Active Directory or Workgroup.

options:
    state:
        description:
        - Whether the specified cifs server should exist or not.
        choices: ['present', 'absent']
        default: 'present'
        type: str

    working_environment_name:
        description:
        - The working environment name where the cifs server will be created.
        type: str

    working_environment_id:
        description:
        - The public ID of the working environment where the cifs server will be created.
        type: str

    client_id:
        description:
        - The connector ID of the Cloud Manager Connector.
        required: true
        type: str

    domain:
        description:
        - The active directory domain name. For CIFS AD only.
        type: str

    dns_domain:
        description:
        - The DNS domain name. For CIFS AD only.
        type: str

    username:
        description:
        - The active directory admin user name. For CIFS AD only.
        type: str

    password:
        description:
        - The active directory admin password. For CIFS AD only.
        type: str

    ip_addresses:
        description:
        - The DNS server IP addresses. For CIFS AD only.
        type: list
        elements: str

    netbios:
        description:
        - The CIFS server NetBIOS name. For CIFS AD only.
        type: str

    organizational_unit:
        description:
        - The organizational unit in which to register the CIFS server. For CIFS AD only.
        type: str

    is_workgroup:
        description:
        - For CIFS workgroup operations, set to true.
        type: bool

    server_name:
        description:
        - The server name. For CIFS workgroup only.
        type: str

    workgroup_name:
        description:
        - The workgroup name. For CIFS workgroup only.
        type: str

notes:
- Support check_mode.
'''

EXAMPLES = '''
- name: Create cifs server with working_environment_id
  netapp.cloudmanager.na_cloudmanager_cifs_server:
    state: present
    working_environment_id: VsaWorkingEnvironment-abcdefgh
    client_id: your_client_id
    refresh_token: your_refresh_token
    domain: example.com
    username: admin
    password: pass
    dns_domain: example.com
    ip_addresses: ["1.0.0.0"]
    netbios: cvoname
    organizational_unit: CN=Computers
'''

RETURN = r''' # '''

from ansible.module_utils.basic import AnsibleModule
import ansible_collections.netapp.cloudmanager.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.cloudmanager.plugins.module_utils.netapp_module import NetAppModule


class NetAppCloudmanagerCifsServer:

    def __init__(self):
        """
        Parse arguments, setup state variables,
        check parameters and ensure request module is installed
        """
        self.argument_spec = netapp_utils.cloudmanager_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, choices=['present', 'absent'], default='present'),
            working_environment_id=dict(required=False, type='str'),
            working_environment_name=dict(required=False, type='str'),
            client_id=dict(required=True, type='str'),
            domain=dict(required=False, type='str'),
            dns_domain=dict(required=False, type='str'),
            username=dict(required=False, type='str'),
            password=dict(required=False, type='str', no_log=True),
            ip_addresses=dict(required=False, type='list', elements='str'),
            netbios=dict(required=False, type='str'),
            organizational_unit=dict(required=False, type='str'),
            is_workgroup=dict(required=False, type='bool'),
            server_name=dict(required=False, type='str'),
            workgroup_name=dict(required=False, type='str'),
        ))
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            required_one_of=[
                ['refresh_token', 'sa_client_id'],
                ['working_environment_name', 'working_environment_id'],
            ],
            required_together=[['sa_client_id', 'sa_secret_key']],
            mutually_exclusive=[
                ('domain', 'server_name'),
                ('dns_domain', 'server_name'),
                ('username', 'server_name'),
                ('password', 'server_name'),
                ('ip_addresses', 'server_name'),
                ('netbios', 'server_name'),
                ('organizational_unit', 'server_name'),
                ('domain', 'workgroup_name'),
                ('dns_domain', 'workgroup_name'),
                ('username', 'workgroup_name'),
                ('password', 'workgroup_name'),
                ('ip_addresses', 'workgroup_name'),
                ('netbios', 'workgroup_name'),
                ('organizational_unit', 'workgroup_name'),
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
        self.headers = {
            'X-Agent-Id': self.rest_api.format_client_id(self.parameters['client_id'])
        }
        if self.parameters.get('working_environment_id'):
            working_environment_detail, error = self.na_helper.get_working_environment_details(self.rest_api, self.headers)
        else:
            working_environment_detail, error = self.na_helper.get_working_environment_details_by_name(self.rest_api,
                                                                                                       self.headers,
                                                                                                       self.parameters['working_environment_name'])
        if working_environment_detail is not None:
            self.parameters['working_environment_id'] = working_environment_detail['publicId']
        else:
            self.module.fail_json(msg="Error: Cannot find working environment: %s" % str(error))
        self.na_helper.set_api_root_path(working_environment_detail, self.rest_api)

    def get_cifs_server(self):
        response, err, dummy = self.rest_api.send_request("GET", "%s/working-environments/%s/cifs" % (
            self.rest_api.api_root_path, self.parameters['working_environment_id']), None, header=self.headers)
        if err is not None:
            self.module.fail_json(changed=False, msg="Error on get_cifs_server: %s, %s" % (str(err), str(response)))
        current_cifs = dict()
        if response is None or len(response) == 0:
            return None
        # only one cifs server exists per working environment.
        for server in response:
            if server.get('activeDirectoryDomain'):
                current_cifs['domain'] = server['activeDirectoryDomain']
            if server.get('dnsDomain'):
                current_cifs['dns_domain'] = server['dnsDomain']
            if server.get('ipAddresses'):
                current_cifs['ip_addresses'] = server['ipAddresses']
            if server.get('organizationalUnit'):
                current_cifs['organizational_unit'] = server['organizationalUnit']
            if server.get('netBIOS'):
                current_cifs['netbios'] = server['netBIOS']
        return current_cifs

    def create_cifs_server(self):
        exclude_list = ['client_id', 'domain', 'netbios', 'username', 'password']
        server = self.na_helper.convert_module_args_to_api(self.parameters, exclude_list)
        if self.parameters.get('domain'):
            server['activeDirectoryDomain'] = self.parameters['domain']
        if self.parameters.get('netbios'):
            server['netBIOS'] = self.parameters['netbios']
        if self.parameters.get('username'):
            server['activeDirectoryUsername'] = self.parameters['username']
        if self.parameters.get('password'):
            server['activeDirectoryPassword'] = self.parameters['password']
        url = "%s/working-environments/%s/cifs" % (self.rest_api.api_root_path,
                                                   self.parameters['working_environment_id'])
        if self.parameters.get('is_workgroup'):
            url = url + "-workgroup"

        response, err, dummy = self.rest_api.send_request("POST", url, None, server, header=self.headers)
        if err is not None:
            self.module.fail_json(changed=False, msg="Error on create_cifs_server failed: %s, %s" % (str(err), str(response)))

    def delete_cifs_server(self):
        response, err, dummy = self.rest_api.send_request("POST", "%s/working-environments/%s/delete-cifs" % (
            self.rest_api.api_root_path, self.parameters['working_environment_id']), None, {}, header=self.headers)
        if err is not None:
            self.module.fail_json(changed=False, msg="Error on delete_cifs_server: %s, %s" % (str(err), str(response)))

    def apply(self):
        current = self.get_cifs_server()
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        if self.na_helper.changed and not self.module.check_mode:
            if cd_action == 'create':
                self.create_cifs_server()
            elif cd_action == 'delete':
                self.delete_cifs_server()
        self.module.exit_json(changed=self.na_helper.changed)


def main():
    '''Main Function'''
    server = NetAppCloudmanagerCifsServer()
    server.apply()


if __name__ == '__main__':
    main()
