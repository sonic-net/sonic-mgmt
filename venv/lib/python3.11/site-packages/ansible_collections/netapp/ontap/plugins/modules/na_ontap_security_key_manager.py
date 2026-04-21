#!/usr/bin/python

# (c) 2019-2025, NetApp, Inc
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """

module: na_ontap_security_key_manager

short_description: NetApp ONTAP security key manager.
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap
version_added: 2.8.0
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>

description:
  - Add or delete or setup key management on NetApp ONTAP.
  - With ZAPI, this module is limited to adding or removing external key servers.  It does not manage certificates.
  - With REST, this module can create an external key manager and certificates are required for creation.
  - With REST, onboard key manager is supported.

options:

  state:
    description:
      - Whether the specified key manager should exist or not.
    choices: ['present', 'absent']
    type: str
    default: 'present'

  ip_address:
    description:
      - The IP address of the external key management server.
      - Mutually exclusive with external and onboard options.
      - Required with ZAPI.
    required: false
    type: str

  tcp_port:
    description:
      - The TCP port on which the key management server listens for incoming connections.
    default: 5696
    type: int

  node:
    description:
      - The node which key management server runs on.
      - Ignored, a warning is raised if present.
      - Deprecated as of 21.22.0, as it was never used.
    type: str

  external:
    description:
      - Configures external key manager.
      - Not supported with ZAPI.
      - Mutually exclusive with ip_address and onboard.
    type: dict
    suboptions:
      client_certificate:
        description:
          - Client certificate name (already installed in the cluster or SVM).
          - Required when creating an external key manager.
        type: str
      server_ca_certificates:
        description:
          - List of server CA certificate names (already installed in the cluster or SVM).
          - Required when creating an external key manager.
        type: list
        elements: str
      servers:
        description:
          - List of external key servers for key management.
          - Format - ip_address:port or FQDN:port.  port defaults to the value of C(tcp_port) when not provided.
          - The order in the list is not preserved if the key-manager already exists.
        type: list
        elements: str
    version_added: 21.23.0

  onboard:
    description:
      - Configures onboard key management.
      - Not supported with ZAPI.
      - Mutually exclusive with ip_address and external .
    type: dict
    suboptions:
      from_passphrase:
        description:
          - The cluster-wide passphrase.
          - Ignored if the onboard key manager does not already exists.
          - Required to change the passphrase.
        type: str
      passphrase:
        description:
          - The cluster-wide passphrase.
        type: str
      synchronize:
        description:
          - Synchronizes missing onboard keys on any node in the cluster.
        type: bool
        default: false
    version_added:  21.23.0

  vserver:
    description:
      - SVM name when using an external key manager.
      - Not supported for onboard key manager.
      - Not supported with ZAPI.
    type: str
    version_added:  21.23.0

notes:
  - Though C(node) is accepted as a parameter, it is not used in the module.
  - Supports check_mode.
  - Only supported at cluster level with ZAPI, or for onboard.
  - ZAPI supports relies on deprecated APIs since ONTAP 9.6.
"""

EXAMPLES = """
# Assuming module_defaults are used to set up hostname, username, password, https, validate_certs
- name: Delete Key Manager
  netapp.ontap.na_ontap_security_key_manager:
    state: absent

- name: Add Key Manager - ZAPI
  netapp.ontap.na_ontap_security_key_manager:
    ip_address: 0.0.0.0

- name: Add/Modify external Key Manager - REST
  netapp.ontap.na_ontap_security_key_manager:
    state: present
    external:
      servers: 10.10.10.10:5696
      client_certificate: kmip_client
      server_ca_certificates: kmip_ca
    vserver: "{{ vserver | default(omit) }}"

- name: Add/Modify external Key Manager - REST
  netapp.ontap.na_ontap_security_key_manager:
    state: present
    external:
      servers: 10.10.10.10:5696,10.10.10.10:5697,10.10.10.11:5696
      client_certificate: kmip_client
      server_ca_certificates: kmip_ca
    vserver: "{{ vserver | default(omit) }}"

- name: Add onboard Key Manager
  netapp.ontap.na_ontap_security_key_manager:
    state: present
    onboard:
      passphrase: "hello, le soleil brille, brille, brille!"

- name: Change passphrase for onboard Key Manager
  netapp.ontap.na_ontap_security_key_manager:
    state: present
    onboard:
      from_passphrase: "hello, le soleil brille, brille, brille!"
      passphrase: "hello, le soleil brille, brille, brille! - 2"
      synchronize: true
"""

RETURN = """
"""

import time
import traceback
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic


class NetAppOntapSecurityKeyManager:
    """class with key manager operations"""

    def __init__(self):
        """Initialize module parameters"""
        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            ip_address=dict(required=False, type='str'),
            node=dict(required=False, type='str'),
            tcp_port=dict(required=False, type='int', default=5696),
            external=dict(type='dict', options=dict(
                client_certificate=dict(type='str'),
                server_ca_certificates=dict(type='list', elements='str'),
                servers=dict(type='list', elements='str'),
            )),
            onboard=dict(type='dict', options=dict(
                from_passphrase=dict(type='str', no_log=True),
                passphrase=dict(type='str', no_log=True),
                synchronize=dict(type='bool', default=False),
            )),
            vserver=dict(type='str'),
        )
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            mutually_exclusive=[
                ('external', 'onboard'),
                ('ip_address', 'onboard'),
                ('ip_address', 'external'),
                ('onboard', 'vserver'),
            ],
            supports_check_mode=True
        )
        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)
        if 'node' in self.parameters:
            self.module.warn('The option "node" is deprecated and should not be used.')
        self.rest_api = netapp_utils.OntapRestAPI(self.module)
        self.use_rest = self.rest_api.is_rest()

        if self.use_rest:
            self.rest_api.fail_if_not_rest_minimum_version('na_ontap_security_key_manager', 9, 7)
            self.uuid = None
            self.scope, self.resource = self.set_scope(self.parameters.get('vserver'))
            # expand parameters to match REST returned info
            self.update_parameters_rest()
        else:
            rest_only = [x for x in ('external', 'onboard', 'vserver') if x in self.parameters]
            if rest_only:
                self.module.fail_json(msg='Error: REST is required for %s option%s.'
                                      % (', '.join(rest_only), 's' if len(rest_only) > 1 else ''))
            if 'ip_address' not in self.parameters:
                self.module.fail_json(msg='missing required arguments: ip_address')
            if not netapp_utils.has_netapp_lib():
                self.module.fail_json(msg=netapp_utils.netapp_lib_is_required())
            self.cluster = netapp_utils.setup_na_ontap_zapi(module=self.module)

    def add_port(self, server):
        """ ONTAP automatically adds :5696 when the port is not present
            We need to add it to make the module idempotent
        """
        return server if ':' in server else '%s:%s' % (server, self.parameters['tcp_port'])

    def update_parameters_rest(self):
        """ expand parameters to match REST returned info
            transform legacy input
        """
        if self.scope == 'svm':
            self.parameters['svm'] = {'name': self.parameters.pop('vserver')}
        servers = self.na_helper.safe_get(self.parameters, ['external', 'servers'])
        if servers:
            # eliminate any empty entry and add port when needed
            self.parameters['external']['servers'] = [{'server': self.add_port(server)} for server in servers if server]

        ip_address = self.parameters.pop('ip_address', None)
        if ip_address:
            ip_address += ':%s' % self.parameters.pop('tcp_port')
            self.parameters['external'] = {'servers': [{'server': ip_address}]}

    @staticmethod
    def set_scope(vserver):
        """ define the scope, and a user friendly resource name"""
        return (
            'cluster' if vserver is None else 'svm',
            'cluster' if vserver is None else 'vserver: %s' % vserver
        )

    def get_key_manager(self):
        """
        get key manager by ip address.
        :return: a dict of key manager
        """
        if self.use_rest:
            return self.get_key_manager_rest()
        key_manager_info = netapp_utils.zapi.NaElement('security-key-manager-get-iter')
        query_details = netapp_utils.zapi.NaElement.create_node_with_children(
            'key-manager-info', **{'key-manager-ip-address': self.parameters['ip_address']})
        query = netapp_utils.zapi.NaElement('query')
        query.add_child_elem(query_details)
        key_manager_info.add_child_elem(query)

        try:
            result = self.cluster.invoke_successfully(key_manager_info, enable_tunneling=False)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error fetching key manager: %s' % to_native(error),
                                  exception=traceback.format_exc())

        return_value = None
        if result.get_child_by_name('num-records') and int(result.get_child_content('num-records')) > 0:
            key_manager = result.get_child_by_name('attributes-list').get_child_by_name('key-manager-info')
            return_value = {}
            if key_manager.get_child_by_name('key-manager-ip-address'):
                return_value['ip_address'] = key_manager.get_child_content('key-manager-ip-address')
            if key_manager.get_child_by_name('key-manager-server-status'):
                return_value['server_status'] = key_manager.get_child_content('key-manager-server-status')
            if key_manager.get_child_by_name('key-manager-tcp-port'):
                return_value['tcp_port'] = int(key_manager.get_child_content('key-manager-tcp-port'))

        return return_value

    def key_manager_setup(self):
        """
        set up external key manager.
        deprecated as of ONTAP 9.6.
        """
        key_manager_setup = netapp_utils.zapi.NaElement('security-key-manager-setup')
        # if specify on-boarding passphrase, it is on-boarding key management.
        # it not, then it's external key management.
        try:
            self.cluster.invoke_successfully(key_manager_setup, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error setting up key manager: %s' % to_native(error),
                                  exception=traceback.format_exc())

    def create_key_manager(self):
        """
        add key manager.
        """
        if self.use_rest:
            return self.create_key_manager_rest()
        key_manager_create = netapp_utils.zapi.NaElement('security-key-manager-add')
        key_manager_create.add_new_child('key-manager-ip-address', self.parameters['ip_address'])
        if self.parameters.get('tcp_port'):
            key_manager_create.add_new_child('key-manager-tcp-port', str(self.parameters['tcp_port']))
        try:
            self.cluster.invoke_successfully(key_manager_create, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error creating key manager: %s' % to_native(error),
                                  exception=traceback.format_exc())

    def delete_key_manager(self):
        """
        delete key manager.
        """
        if self.use_rest:
            return self.delete_key_manager_rest()
        key_manager_delete = netapp_utils.zapi.NaElement('security-key-manager-delete')
        key_manager_delete.add_new_child('key-manager-ip-address', self.parameters['ip_address'])
        try:
            self.cluster.invoke_successfully(key_manager_delete, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error deleting key manager: %s' % to_native(error),
                                  exception=traceback.format_exc())

    def _get_security_certificate_uuid_rest_any(self, query, fields):
        api = 'security/certificates'
        query['scope'] = self.scope
        if self.scope == 'svm':
            # try first at SVM level
            query['svm.name'] = self.parameters['svm']['name']
            record, error = rest_generic.get_one_record(self.rest_api, api, query, fields)
            if record and error is None:
                return record, error
            # retry at cluster scope
            del query['svm.name']
        query['scope'] = 'cluster'
        return rest_generic.get_one_record(self.rest_api, api, query, fields)

    def get_security_certificate_uuid_rest_97(self, name, type):
        query = {'common_name': name, 'type': type}
        fields = 'uuid,common_name,type'
        return self._get_security_certificate_uuid_rest_any(query, fields)

    def get_security_certificate_uuid_rest_98(self, name):
        query = {'name': name}
        fields = 'uuid,name,common_name,type'
        return self._get_security_certificate_uuid_rest_any(query, fields)

    def get_security_certificate_uuid_rest(self, name, type):
        if self.rest_api.meets_rest_minimum_version(self.use_rest, 9, 8):
            record, error = self.get_security_certificate_uuid_rest_98(name)
            message = 'certificate %s not found, retrying with common_name and type %s.'\
                      % (name, type)
        else:
            record, error = None, None
            message = 'name is not supported in 9.6 or 9.7, using common_name %s and type %s.'\
                      % (name, type)
        if not error and not record:
            self.module.warn(message)
            record, error = self.get_security_certificate_uuid_rest_97(name, type)
        if not error and not record:
            error = 'not found'
        if error:
            self.module.fail_json(msg='Error fetching security certificate info for %s of type: %s on %s: %s.' % (name, type, self.resource, error))
        return record['uuid']

    def get_key_manager_rest(self):
        api = 'security/key-managers'
        query = {'scope': self.scope}
        fields = 'status,external,uuid,onboard'
        if self.scope == 'svm':
            query['svm.name'] = self.parameters['svm']['name']
        record, error = rest_generic.get_one_record(self.rest_api, api, query, fields)
        if error:
            if self.scope == 'svm' and 'SVM "%s" does not exist' % self.parameters['svm']['name'] in error:
                return None
            self.module.fail_json(msg='Error fetching key manager info for %s: %s' % (self.resource, error))
        if record:
            self.uuid = record['uuid']
            if 'external' in record and (self.na_helper.safe_get(record, ['onboard', 'enabled']) is False):
                del record['onboard']
            if 'external' in record and 'servers' in record['external']:
                # remove extra fields that are readonly and not relevant for modify
                record['external']['servers'] = [{'server': server['server']} for server in record['external']['servers']]
            self.na_helper.remove_hal_links(record)

        return record

    def create_body(self, params):
        if 'external' in params:
            body = {'external': self.na_helper.filter_out_none_entries(params['external'])}
        elif 'onboard' in params:
            body = {'onboard': self.na_helper.filter_out_none_entries(params['onboard'])}
            body['onboard'].pop('from_passphrase', None)
        else:
            return
        if 'svm' in self.parameters:
            body['svm'] = self.na_helper.filter_out_none_entries(self.parameters['svm'])
        return body

    def create_key_manager_rest(self, retrying=None):
        api = 'security/key-managers'
        body = self.create_body(self.parameters)
        dummy, error = rest_generic.post_async(self.rest_api, api, body)
        if error:
            # ONTAP returns no record if external manager is configured but no server is present
            if not retrying and ('already has external key management configured' in error
                                 or 'External key management already configured' in error):
                self.module.warn("deleting and recreating key manager as no key server is configured.")
                self.delete_key_manager_rest()
                time.sleep(5)
                return self.create_key_manager_rest('retrying')
            resource = 'cluster' if self.parameters.get('vserver') is None else self.parameters['vserver']
            self.module.fail_json(msg='Error creating key manager for %s: %s' % (resource, error))

    def modify_key_manager_rest(self, modify, current=None, return_error=False):
        # external key servers cannot be updated in PATCH, they are handled later
        key_servers = self.na_helper.safe_get(modify, ['external', 'servers'])
        if key_servers:
            del modify['external']['servers']
            if not modify['external']:
                del modify['external']
        if modify:
            api = 'security/key-managers'
            body = self.create_body(modify)
            dummy, error = rest_generic.patch_async(self.rest_api, api, self.uuid, body)
            if error:
                if return_error:
                    return error
                resource = 'cluster' if self.parameters.get('vserver') is None else self.parameters['vserver']
                self.module.fail_json(msg='Error modifying key manager for %s: %s' % (resource, error))
        if key_servers:
            self.update_key_server_list(current)
        return None

    def check_passphrase_rest(self, passphrase):
        """ API does not return the passphrase
            In order to check for idempotency, check if the desired passphrase is already active"""
        params = {
            'onboard': {
                'existing_passphrase': passphrase,
                'passphrase': passphrase,
            }
        }
        error = self.modify_key_manager_rest(params, return_error=True)
        if not error:
            return 'unexpected_success in check_passphrase_rest', error
        if 'Cluster-wide passphrase is incorrect.' in error:
            return 'incorrect_passphrase', error
        if 'New passphrase cannot be same as the old passphrase.' in error or \
                'The new passphrase is same as old passphrase.' in error:
            return 'current_passphrase', error
        self.module.warn('Unexpected response in check_passphrase_rest: %s' % error)
        return 'unexpected_error in check_passphrase_rest', error

    def delete_key_manager_rest(self):
        api = 'security/key-managers'
        if self.uuid is None:
            # ONTAP does not return a record when an external key manager is configured without any external server
            query = {'scope': self.scope}
            if self.scope == 'svm':
                query['svm.name'] = self.parameters['svm']['name']
        else:
            query = None
        dummy, error = rest_generic.delete_async(self.rest_api, api, self.uuid, query)
        if error:
            resource = 'cluster' if self.parameters.get('vserver') is None else self.parameters['vserver']
            self.module.fail_json(msg='Error deleting key manager for %s: %s' % (resource, error))

    def validate_delete_action(self, current):
        return

    def validate_modify(self, current, modify):
        error = None if self.use_rest else 'modify is not supported with ZAPI, new values: %s, current values: %s' % (modify, current)
        if error:
            self.module.fail_json(msg='Error, cannot modify existing configuraton: %s' % error)

    def substitute_certificate_uuids(self, params):
        if 'external' not in params:
            return
        certificate = self.na_helper.safe_get(params, ['external', 'client_certificate'])
        if certificate:
            params['external']['client_certificate'] = {'uuid': self.get_security_certificate_uuid_rest(certificate, 'client')}
        certificates = self.na_helper.safe_get(params, ['external', 'server_ca_certificates'])
        if certificates:
            params['external']['server_ca_certificates'] = [{'uuid': self.get_security_certificate_uuid_rest(certificate, 'server_ca')}
                                                            for certificate in certificates]

    def is_passphrase_update_required(self, passphrase, from_passphrase):
        check_new, __ = self.check_passphrase_rest(passphrase)
        if check_new == 'current_passphrase':
            return False
        check_old, error = self.check_passphrase_rest(from_passphrase)
        if check_old == 'incorrect_passphrase' and check_new == 'incorrect_passphrase':
            self.module.fail_json(msg='Error: neither from_passphrase nor passphrase match installed passphrase: %s' % error)
        # if check_old is current, we're good to change the passphrase.  For other errors, we'll just try again, we already warned.
        return True

    def force_onboard_actions(self):
        """ synchronize and passphrase are not returned in GET so we need to be creative """
        if 'onboard' not in self.parameters:
            return None, None
        passphrase = self.na_helper.safe_get(self.parameters, ['onboard', 'passphrase'])
        # do we need to synchronize
        modify_sync = None
        if self.na_helper.safe_get(self.parameters, ['onboard', 'synchronize']):
            if passphrase is None:
                self.module.fail_json(msg='Error: passphrase is required for synchronize.')
            modify_sync = {'onboard': {
                'synchronize': True,
                'existing_passphrase': passphrase
            }}
        # do we need to update the passphrase
        modify_passphrase = None
        from_passphrase = self.na_helper.safe_get(self.parameters, ['onboard', 'from_passphrase'])
        if passphrase and not from_passphrase:
            check_new, __ = self.check_passphrase_rest(passphrase)
            if check_new == 'current_passphrase':
                self.module.warn('Passphrase was not changed: The new passphrase is same as old passphrase.')
            else:
                self.module.warn('Passphrase was ignored as existing_passphrase was not given.')
        if not passphrase and from_passphrase and not modify_sync:
            self.module.warn('from_passphrase is ignored')
        if passphrase and from_passphrase and self.is_passphrase_update_required(passphrase, from_passphrase):
            modify_passphrase = {'onboard': {
                'passphrase': passphrase,
                'existing_passphrase': from_passphrase
            }}
        # wrapping up
        if modify_passphrase or modify_sync:
            self.na_helper.changed = True
        return modify_passphrase, modify_sync

    def validate_type_change(self, current):
        """present moving from onboard to external and reciprocally"""
        error = None
        if 'onboard' in current and 'external' in self.parameters:
            error = 'onboard key-manager is already installed, it needs to be deleted first.'
        if 'external' in current and 'onboard' in self.parameters:
            error = 'external key-manager is already installed, it needs to be deleted first.'
        if error:
            self.module.fail_json(msg='Error, cannot modify existing configuraton: %s' % error)

    def local_get_modified_attributes(self, current):
        modify = self.na_helper.get_modified_attributes(current, self.parameters)
        if current and 'external' in self.parameters and not self.na_helper.safe_get(modify, ['external', 'servers']):
            current_servers = self.na_helper.safe_get(current, ['external', 'servers'])
            desired_servers = self.na_helper.safe_get(self.parameters, ['external', 'servers'])
            # order matters for key servers
            if current_servers != desired_servers:
                if 'external' not in modify:
                    modify['external'] = {}
                modify['external']['servers'] = desired_servers
                self.na_helper.changed = True
        return modify

    def add_external_server_rest(self, server):
        api = 'security/key-managers/%s/key-servers' % self.uuid
        body = {
            'server': server
        }
        dummy, error = rest_generic.post_async(self.rest_api, api, body)
        if error:
            self.module.fail_json(msg='Error adding external key server %s: %s' % (server, error))

    def remove_external_server_rest(self, server):
        api = 'security/key-managers/%s/key-servers' % self.uuid
        dummy, error = rest_generic.delete_async(self.rest_api, api, server)
        if error:
            self.module.fail_json(msg='Error removing external key server %s: %s' % (server, error))

    def update_key_server_list(self, current):
        desired_servers = self.na_helper.safe_get(self.parameters, ['external', 'servers'])
        if desired_servers is None:
            return
        desired_servers = [server['server'] for server in desired_servers]
        current_servers = self.na_helper.safe_get(current, ['external', 'servers']) or []
        current_servers = [server['server'] for server in current_servers]
        for server in current_servers:
            if server not in desired_servers:
                self.remove_external_server_rest(server)
        for server in desired_servers:
            if server not in current_servers:
                self.add_external_server_rest(server)

    def apply(self):
        if not self.use_rest:
            self.key_manager_setup()
        current = self.get_key_manager()
        if current:
            self.validate_type_change(current)
        if self.parameters['state'] == 'present':
            self.substitute_certificate_uuids(self.parameters)
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        modify = self.local_get_modified_attributes(current) if cd_action is None else None
        # with onboard, changing a passphrase or synchronizing cannot be done in the same PATCH request
        modify_passphrase, modify_sync = self.force_onboard_actions() if cd_action is None and current else (None, None)
        if cd_action == 'delete' and self.use_rest:
            self.validate_delete_action(current)
        if modify:
            self.validate_modify(current, modify)
        if self.na_helper.changed and not self.module.check_mode:
            if cd_action == 'create':
                self.create_key_manager()
            elif cd_action == 'delete':
                self.delete_key_manager()
            elif modify:
                self.modify_key_manager_rest(modify, current)
            elif modify_passphrase:
                self.modify_key_manager_rest(modify_passphrase)
            elif modify_sync:
                self.modify_key_manager_rest(modify_sync)
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action, modify)
        self.module.exit_json(**result)


def main():
    """Apply volume operations from playbook"""
    obj = NetAppOntapSecurityKeyManager()
    obj.apply()


if __name__ == '__main__':
    main()
