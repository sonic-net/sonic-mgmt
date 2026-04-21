#!/usr/bin/python

# (c) 2022-2025, NetApp, Inc
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function
__metaclass__ = type

'''
na_ontap_security_ssh
'''


DOCUMENTATION = '''
module: na_ontap_security_ssh
short_description: NetApp ONTAP security ssh
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap_rest
version_added: 21.24.0
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
  - Modify SSH server configuration of SVM on ONTAP
options:
  state:
    description:
      - SSH service is always enabled.
    choices: ['present']
    type: str
    default: present
  vserver:
    description:
      - Name of the vserver to use for vserver scope.
      - If absent or null, cluster scope is assumed.
    type: str
  ciphers:
    description:
      - Ciphers for encrypting the data.
      - Example list [ aes256_ctr, aes192_ctr, aes128_ctr, aes256_cbc, aes192_cbc ]
    type: list
    elements: str
  key_exchange_algorithms:
    description:
      - Key exchange algorithms.
      - Example list [ diffie_hellman_group_exchange_sha256, diffie_hellman_group14_sha1 ]
    type: list
    elements: str
  mac_algorithms:
    description:
      - MAC algorithms.
      - Example list [ hmac_sha1, hmac_sha2_512_etm ]
    type: list
    elements: str
  max_authentication_retry_count:
    description:
      - Maximum authentication retries allowed before closing the connection.
      - Minimum value is 2 and maximum is 6.
      - Default value is 2.
    type: int
  host_key_algorithms:
    description:
      - Enables the specified host key algorithms for the Vserver. It replaces all existing host key algorithms with the specified settings.
      - The host key algorithm "ssh_ed25519" can be configured only in non-FIPS mode.
      - Requires ONTAP 9.16.1 and later.
      - Example list [ "ecdsa_sha2_nistp256", "ssh_rsa", "ssh_ed25519" ]
    type: list
    elements: str
    version_added: 23.2.0

notes:
  - Removing all SSH key exchange algorithms is not supported. SSH login would fail.
  - This module is only for REST.
'''

EXAMPLES = """
- name: Modify SSH algorithms
  netapp.ontap.na_ontap_security_ssh:
    vserver: vserverName
    ciphers: ["aes256_ctr", "aes192_ctr"]
    key_exchange_algorithms: ["diffie_hellman_group_exchange_sha256"]
    mac_algorithms: ["hmac_sha1"]
    max_authentication_retry_count: 6
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Modify SSH algorithms at cluster level
  netapp.ontap.na_ontap_security_ssh:
    vserver:
    ciphers: ["aes256_ctr", "aes192_ctr"]
    key_exchange_algorithms: ["diffie_hellman_group_exchange_sha256"]
    mac_algorithms: ["hmac_sha1"]
    max_authentication_retry_count: 6
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Modify SSH algorithms at cluster level
  netapp.ontap.na_ontap_security_ssh:
    ciphers: ["aes256_ctr", "aes192_ctr"]
    key_exchange_algorithms: ["diffie_hellman_group_exchange_sha256"]
    mac_algorithms: ["hmac_sha1"]
    max_authentication_retry_count: 6
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
"""

RETURN = """
"""

from ansible.module_utils.basic import AnsibleModule
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic


class NetAppOntapSecuritySSH:
    """ object initialize and class methods """
    def __init__(self):
        self.argument_spec = netapp_utils.na_ontap_rest_only_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present'], default='present'),
            vserver=dict(required=False, type='str'),
            ciphers=dict(required=False, type='list', elements='str'),
            key_exchange_algorithms=dict(required=False, type='list', elements='str', no_log=False),
            mac_algorithms=dict(required=False, type='list', elements='str'),
            max_authentication_retry_count=dict(required=False, type='int'),
            host_key_algorithms=dict(required=False, type='list', elements='str', no_log=False),
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )
        self.na_helper = NetAppModule(self)
        self.parameters = self.na_helper.set_parameters(self.module.params)
        self.svm_uuid = None
        self.rest_api = netapp_utils.OntapRestAPI(self.module)
        self.rest_api.fail_if_not_rest_minimum_version('na_ontap_security_ssh', 9, 10, 1)
        self.use_rest = self.rest_api.is_rest_supported_properties(self.parameters, None, [['host_key_algorithms', (9, 16, 1)]])
        self.safe_strip()

    def safe_strip(self):
        """ strip the left and right spaces of string and also removes an empty string"""
        for option in ('ciphers', 'key_exchange_algorithms', 'mac_algorithms'):
            if option in self.parameters:
                self.parameters[option] = [item.strip() for item in self.parameters[option] if len(item.strip())]
                # Validation of input parameters
                if self.parameters[option] == []:
                    self.module.fail_json(msg="Removing all SSH %s is not supported. SSH login would fail. "
                                              "There must be at least one %s associated with the SSH configuration." % (option, option))
        return

    def get_security_ssh_rest(self):
        '''
        Retrieves the SSH server configuration for the SVM or cluster.
        '''
        fields = ['key_exchange_algorithms', 'ciphers', 'mac_algorithms', 'max_authentication_retry_count']
        if self.parameters.get('host_key_algorithms'):
            fields.append('host_key_algorithms')
        query = {}
        if self.parameters.get('vserver'):
            api = 'security/ssh/svms'
            query['svm.name'] = self.parameters['vserver']
            fields.append('svm.uuid')
        else:
            api = 'security/ssh'
        query['fields'] = ','.join(fields)
        record, error = rest_generic.get_one_record(self.rest_api, api, query)
        if error:
            self.module.fail_json(msg=error)
        return record

    def modify_security_ssh_rest(self, modify):
        '''
        Updates the SSH server configuration for the specified SVM.
        '''
        if self.parameters.get('vserver'):
            if self.svm_uuid is None:
                self.module.fail_json(msg="Error: no uuid found for the SVM")
            api = 'security/ssh/svms'
        else:
            api = 'security/ssh'
        body = {}
        for option in ('ciphers', 'key_exchange_algorithms', 'mac_algorithms', 'max_authentication_retry_count', 'host_key_algorithms'):
            if option in modify:
                body[option] = modify[option]
        if body:
            dummy, error = rest_generic.patch_async(self.rest_api, api, self.svm_uuid, body)
            if error:
                self.module.fail_json(msg=error)

    def apply(self):
        current = self.get_security_ssh_rest()
        self.svm_uuid = self.na_helper.safe_get(current, ['svm', 'uuid']) if current and self.parameters.get('vserver') else None
        modify = self.na_helper.get_modified_attributes(current, self.parameters)
        if self.na_helper.changed and not self.module.check_mode:
            self.modify_security_ssh_rest(modify)
        result = netapp_utils.generate_result(self.na_helper.changed, modify=modify)
        self.module.exit_json(**result)


def main():
    """ Create object and call apply """
    ssh_obj = NetAppOntapSecuritySSH()
    ssh_obj.apply()


if __name__ == '__main__':
    main()
