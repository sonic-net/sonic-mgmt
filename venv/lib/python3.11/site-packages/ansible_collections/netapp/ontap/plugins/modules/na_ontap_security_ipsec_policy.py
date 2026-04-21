#!/usr/bin/python

# (c) 2022-2025, NetApp, Inc. GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
module: na_ontap_security_ipsec_policy
short_description: NetApp ONTAP module to create, modify or delete security IPsec policy.
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap_rest
version_added: '22.1.0'
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
  - Create, modify or delete security IPsec policy.
options:
  state:
    description:
      - Create or delete security IPsec policy.
    choices: ['present', 'absent']
    type: str
    default: present
  name:
    description:
      - Name of the security IPsec policy
    type: str
    required: true
  action:
    description:
      - Action for the IPsec policy.
      - Cannot modify after create.
    type: str
    choices: ['bypass', 'discard', 'esp_transport', 'esp_udp']
  authentication_method:
    description:
      - Authentication method for the IPsec policy.
      - Supported from 9.10.1 or later.
      - Cannot modify after create.
    type: str
    choices: ['none', 'psk', 'pki']
  certificate:
    description:
      - Certificate for the IPsec policy.
      - Supported from 9.10.1 or later.
      - Required when C(authentication_method) is 'pki' in create.
    type: str
  enabled:
    description:
      - Indicates whether or not the policy is enabled.
    type: bool
  ipspace:
    description:
      - IPspace name where C(svm) exist.
    type: str
  local_endpoint:
    description:
      - Local endpoint for the IPsec policy.
    type: dict
    suboptions:
      address:
        description:
          - IPv4 or IPv6 address.
        type: str
        required: true
      netmask:
        description:
          - Input as netmask length (16) or IPv4 mask (255.255.0.0).
          - For IPv6, the default value is 64 with a valid range of 1 to 127.
        type: str
        required: true
      port:
        description:
          - Application port to be covered by the IPsec policy, example 23.
        type: str
  remote_endpoint:
    description:
      - remote endpoint for the IPsec policy.
    type: dict
    suboptions:
      address:
        description:
          - IPv4 or IPv6 address.
        type: str
        required: true
      netmask:
        description:
          - Input as netmask length (16) or IPv4 mask (255.255.0.0).
          - For IPv6, the default value is 64 with a valid range of 1 to 127.
        type: str
        required: true
      port:
        description:
          - Application port to be covered by the IPsec policy, example 23 or 23-23.
        type: str
  local_identity:
    description:
      - local IKE endpoint's identity for authentication purpose.
    type: str
  remote_identity:
    description:
      - remote IKE endpoint's identity for authentication purpose.
    type: str
  protocol:
    description:
      - protocol to be protected by by this policy.
      - example 'any' or '0', 'tcp', 'udp' or protocol number.
    type: str
  secret_key:
    description:
      - Pre-shared key for IKE negotiation.
      - Required when C(authentication_method) is 'psk' in create.
      - Cannot modify after create.
    type: str
  svm:
    description:
      - The name of the SVM.
      - Required when creating security IPsec policy.
    type: str

notes:
  - Supports check_mode.
  - Only supported with REST and requires ONTAP 9.8 or later.
"""

EXAMPLES = """
- name: Create security IPsec policy with pre-shared Keys.
  netapp.ontap.na_ontap_security_ipsec_policy:
    name: ipsec_policy_psk
    ipspace: Default
    svm: ansibleSVM
    authentication_method: psk
    secret_key: "{{ secret_key }}"
    action: esp_transport
    local_endpoint:
      address: 10.23.43.23
      netmask: 24
      port: 201
    remote_endpoint:
      address: 10.23.43.30
      netmask: 24
      port: 205
    protocol: tcp
    enabled: true
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: "{{ validate_certs }}"

- name: Create security IPsec policy with certificates.
  netapp.ontap.na_ontap_security_ipsec_policy:
    name: ipsec_policy_pki
    ipspace: Default
    svm: ansibleSVM
    authentication_method: pki
    certificate: "{{ cert_name }}"
    action: esp_transport
    local_endpoint:
      address: 10.23.43.23
      netmask: 24
      port: 201
    remote_endpoint:
      address: 10.23.43.30
      netmask: 24
      port: 205
    protocol: tcp
    enabled: true
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: "{{ validate_certs }}"

- name: Create security IPsec policy without psk or certificates.
  netapp.ontap.na_ontap_security_ipsec_policy:
    name: ipsec_policy_none
    ipspace: Default
    svm: ansibleSVM
    action: bypass
    local_endpoint:
      address: 10.23.43.23
      netmask: 24
      port: 201
    remote_endpoint:
      address: 10.23.43.30
      netmask: 24
      port: 205
    protocol: tcp
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: "{{ validate_certs }}"

- name: Modify security IPsec policy local, remote end_point.
  netapp.ontap.na_ontap_security_ipsec_policy:
    name: ipsec_policy_pki
    ipspace: Default
    svm: ansibleSVM
    authentication_method: pki
    certificate: "{{ cert_name }}"
    action: esp_transport
    local_endpoint:
      address: 10.23.43.50
      netmask: 24
      port: 201
    remote_endpoint:
      address: 10.23.43.60
      netmask: 24
      port: 205
    protocol: tcp
    enabled: true
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: "{{ validate_certs }}"

- name: Modify security IPsec protocol, enable options.
  netapp.ontap.na_ontap_security_ipsec_policy:
    name: ipsec_policy_pki
    ipspace: Default
    svm: ansibleSVM
    authentication_method: pki
    certificate: "{{ cert_name }}"
    action: esp_transport
    local_endpoint:
      address: 10.23.43.50
      netmask: 24
      port: 201
    remote_endpoint:
      address: 10.23.43.60
      netmask: 24
      port: 205
    protocol: udp
    enabled: false
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: "{{ validate_certs }}"

- name: Delete security IPsec policy.
  netapp.ontap.na_ontap_security_ipsec_policy:
    name: ipsec_policy_pki
    svm: ansibleSVM
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
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic, netapp_ipaddress


class NetAppOntapSecurityIPsecPolicy:
    def __init__(self):
        self.argument_spec = netapp_utils.na_ontap_rest_only_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            name=dict(required=True, type='str'),
            action=dict(required=False, type='str', choices=['bypass', 'discard', 'esp_transport', 'esp_udp']),
            authentication_method=dict(required=False, type='str', choices=['none', 'psk', 'pki']),
            certificate=dict(required=False, type='str'),
            enabled=dict(required=False, type='bool'),
            ipspace=dict(required=False, type='str'),
            local_endpoint=dict(required=False, type='dict', options=dict(
                address=dict(required=True, type='str'),
                netmask=dict(required=True, type='str'),
                port=dict(required=False, type='str')
            )),
            local_identity=dict(required=False, type='str'),
            remote_identity=dict(required=False, type='str'),
            protocol=dict(required=False, type='str'),
            remote_endpoint=dict(required=False, type='dict', options=dict(
                address=dict(required=True, type='str'),
                netmask=dict(required=True, type='str'),
                port=dict(required=False, type='str')
            )),
            secret_key=dict(required=False, type='str', no_log=True),
            svm=dict(required=False, type='str')
        ))
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            mutually_exclusive=[('secret_key', 'certificate')],
            required_if=[
                ('authentication_method', 'psk', ['secret_key']),
                ('authentication_method', 'pki', ['certificate'])
            ],
            supports_check_mode=True
        )
        self.uuid = None
        self.na_helper = NetAppModule(self.module)
        self.parameters = self.na_helper.check_and_set_parameters(self.module)
        self.rest_api = netapp_utils.OntapRestAPI(self.module)
        self.rest_api.fail_if_not_rest_minimum_version('na_ontap_security_ipsec_policy', 9, 8)
        partially_supported_rest_properties = [['authentication_method', (9, 10, 1)], ['certificate', (9, 10, 1)]]
        self.rest_api.is_rest_supported_properties(self.parameters, None, partially_supported_rest_properties)
        self.parameters = self.na_helper.filter_out_none_entries(self.parameters)
        if self.parameters['state'] == 'present':
            self.validate_ipsec()

    def validate_ipsec(self):
        """
        validate ipsec options.
        """
        for end_point in ['local_endpoint', 'remote_endpoint']:
            if self.parameters.get(end_point):
                self.parameters[end_point]['address'] = netapp_ipaddress.validate_and_compress_ip_address(self.parameters[end_point]['address'], self.module)
                self.parameters[end_point]['netmask'] = str(netapp_ipaddress.netmask_to_netmask_length(self.parameters[end_point]['address'],
                                                                                                       self.parameters[end_point]['netmask'], self.module))
                # ONTAP returns port in port ranges. 120 set is returned as 120-120
                if self.parameters[end_point].get('port') and '-' not in self.parameters[end_point]['port']:
                    self.parameters[end_point]['port'] = self.parameters[end_point]['port'] + '-' + self.parameters[end_point]['port']
        # if action is bypass/discard and auth_method is psk/pki then security_key/certificate will be ignored in REST.
        # so delete the authentication_method, secret_key and certificate to avoid idempotent issue.
        if self.parameters.get('action') in ['bypass', 'discard'] and self.parameters.get('authentication_method') != 'none':
            msg = "The IPsec action is %s, which does not provide packet protection. The authentication_method and " % self.parameters['action']
            self.parameters.pop('authentication_method', None)
            if self.parameters.get('secret_key'):
                del self.parameters['secret_key']
                self.module.warn(msg + 'secret_key options are ignored')
            if self.parameters.get('certificate'):
                del self.parameters['certificate']
                self.module.warn(msg + 'certificate options are ignored')
        # mapping protocol number to protocol to avoid idempotency issue.
        protocols_info = {'6': 'tcp', '17': 'udp', '0': 'any'}
        if self.parameters.get('protocol') in protocols_info:
            self.parameters['protocol'] = protocols_info[self.parameters['protocol']]

    def get_security_ipsec_policy(self):
        """
        Get security ipsec policy.
        """
        api = 'security/ipsec/policies'
        query = {
            'name': self.parameters['name'],
            'fields': 'uuid,enabled,local_endpoint,local_identity,remote_identity,protocol,remote_endpoint,action'
        }
        if self.parameters.get('authentication_method'):
            query['fields'] += ',authentication_method'
        if self.parameters.get('certificate'):
            query['fields'] += ',certificate'
        if self.parameters.get('svm'):
            query['svm.name'] = self.parameters['svm']
        else:
            query['scope'] = 'cluster'
        # Cannot get current IPsec policy with ipspace - burt1519419
        # if self.parameters.get('ipspace'):
            # query['ipspace.name'] = self.parameters['ipspace']
        record, error = rest_generic.get_one_record(self.rest_api, api, query)
        if error:
            self.module.fail_json(msg='Error fetching security ipsec policy %s: %s' % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())
        if record:
            self.uuid = record['uuid']
            return {
                'action': self.na_helper.safe_get(record, ['action']),
                'authentication_method': self.na_helper.safe_get(record, ['authentication_method']),
                'certificate': self.na_helper.safe_get(record, ['certificate', 'name']),
                'enabled': self.na_helper.safe_get(record, ['enabled']),
                'local_endpoint': self.na_helper.safe_get(record, ['local_endpoint']),
                'local_identity': self.na_helper.safe_get(record, ['local_identity']),
                'protocol': self.na_helper.safe_get(record, ['protocol']),
                'remote_endpoint': self.na_helper.safe_get(record, ['remote_endpoint']),
                'remote_identity': self.na_helper.safe_get(record, ['remote_identity'])
            }
        return None

    def create_security_ipsec_policy(self):
        """
        Create security ipsec policy
        """
        api = 'security/ipsec/policies'
        dummy, error = rest_generic.post_async(self.rest_api, api, self.form_create_modify_body())
        if error:
            self.module.fail_json(msg='Error creating security ipsec policy %s: %s.' % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def modify_security_ipsec_policy(self, modify):
        """
        Modify security ipsec policy.
        """
        api = 'security/ipsec/policies'
        dummy, error = rest_generic.patch_async(self.rest_api, api, self.uuid, self.form_create_modify_body(modify))
        if error:
            self.module.fail_json(msg='Error modifying security ipsec policy %s: %s.' % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def delete_security_ipsec_policy(self):
        """
        Delete security ipsec policy.
        """
        api = 'security/ipsec/policies'
        dummy, error = rest_generic.delete_async(self.rest_api, api, self.uuid)
        if error:
            self.module.fail_json(msg='Error deleting security ipsec policy %s: %s.' % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def form_create_modify_body(self, params=None):
        """
        Returns body for create or modify.
        """
        if params is None:
            params = self.parameters
        body = {}
        keys = ['name', 'action', 'authentication_method', 'enabled', 'secret_key',
                'local_endpoint', 'local_identity', 'remote_identity', 'protocol', 'remote_endpoint']
        for key in keys:
            if key in params:
                body[key] = self.parameters[key]
        if 'certificate' in params:
            body['certificate.name'] = self.parameters['certificate']
        if 'ipspace' in params:
            body['ipspace.name'] = self.parameters['ipspace']
        if 'svm' in params:
            body['svm.name'] = self.parameters['svm']
        return body

    def apply(self):
        current = self.get_security_ipsec_policy()
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        if cd_action is None:
            modify = self.na_helper.get_modified_attributes(current, self.parameters)
            error_keys = [key for key in modify if key in ['authentication_method', 'action']]
            if error_keys:
                plural = 's' if len(error_keys) > 1 else ''
                self.module.fail_json(msg="Error: cannot modify option%s - %s." % (plural, ", ".join(error_keys)))
            # Expected ONTAP to throw error but restarts instead, if try to set certificate where auth_method is none.
            if modify.get('certificate') and current['authentication_method'] == 'none':
                self.module.fail_json(msg="Error: cannot set certificate for IPsec policy where authentication_method is none")
        if self.na_helper.changed and not self.module.check_mode:
            if cd_action == 'create':
                self.create_security_ipsec_policy()
            elif cd_action == 'delete':
                self.delete_security_ipsec_policy()
            else:
                self.modify_security_ipsec_policy(modify)
        self.module.exit_json(changed=self.na_helper.changed)


def main():
    ipsec_obj = NetAppOntapSecurityIPsecPolicy()
    ipsec_obj.apply()


if __name__ == '__main__':
    main()
