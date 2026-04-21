#!/usr/bin/python

# (c) 2018-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
  - Create/Delete vserver peer
extends_documentation_fragment:
  - netapp.ontap.netapp.na_ontap
  - netapp.ontap.netapp.na_ontap_peer
module: na_ontap_vserver_peer
options:
  state:
    choices: ['present', 'absent']
    type: str
    description:
    - Whether the specified vserver peer should exist or not.
    default: present
  vserver:
    description:
    - Specifies name of the source Vserver in the relationship.
    required: true
    type: str
  applications:
    type: list
    elements: str
    description:
    - List of applications which can make use of the peering relationship.
    - FlexCache supported from ONTAP 9.5 onwards.
  peer_vserver:
    description:
    - Specifies name of the peer Vserver in the relationship.
    required: true
    type: str
  peer_cluster:
    description:
    - Specifies name of the peer Cluster.
    - Required for creating the vserver peer relationship with a remote cluster
    type: str
  local_name_for_peer:
    description:
    - Specifies local name of the peer Vserver in the relationship.
    - Use this if you see "Error creating vserver peer ... Vserver name conflicts with one of the following".
    type: str
  local_name_for_source:
    description:
    - Specifies local name of the source Vserver in the relationship.
    - Use this if you see "Error accepting vserver peer ... System generated a name for the peer Vserver because of a naming conflict".
    type: str
  dest_hostname:
    description:
    - DEPRECATED - please use C(peer_options).
    - Destination hostname or IP address.
    - Required for creating the vserver peer relationship with a remote cluster.
    type: str
  dest_username:
    description:
    - DEPRECATED - please use C(peer_options).
    - Destination username.
    - Optional if this is same as source username.
    type: str
  dest_password:
    description:
    - DEPRECATED - please use C(peer_options).
    - Destination password.
    - Optional if this is same as source password.
    type: str
short_description: NetApp ONTAP Vserver peering
version_added: 2.7.0
'''

EXAMPLES = """
- name: Source vserver peer create
  netapp.ontap.na_ontap_vserver_peer:
    state: present
    peer_vserver: ansible2
    peer_cluster: ansibleCluster
    local_name_for_peer: peername
    local_name_for_source: sourcename
    vserver: ansible
    applications: ['snapmirror']
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    peer_options:
      hostname: "{{ netapp_dest_hostname }}"

- name: vserver peer delete
  netapp.ontap.na_ontap_vserver_peer:
    state: absent
    peer_vserver: ansible2
    vserver: ansible
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Source vserver peer create - different credentials
  netapp.ontap.na_ontap_vserver_peer:
    state: present
    peer_vserver: ansible2
    peer_cluster: ansibleCluster
    local_name_for_peer: peername
    local_name_for_source: sourcename
    vserver: ansible
    applications: ['snapmirror']
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    peer_options:
      hostname: "{{ netapp_dest_hostname }}"
      cert_filepath: "{{ cert_filepath }}"
      key_filepath: "{{ key_filepath }}"
"""

RETURN = """
"""

import traceback
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils.netapp import OntapRestAPI
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic


class NetAppONTAPVserverPeer:
    """
    Class with vserver peer methods
    """

    def __init__(self):

        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            vserver=dict(required=True, type='str'),
            peer_vserver=dict(required=True, type='str'),
            peer_cluster=dict(required=False, type='str'),
            local_name_for_peer=dict(required=False, type='str'),
            local_name_for_source=dict(required=False, type='str'),
            applications=dict(required=False, type='list', elements='str'),
            peer_options=dict(type='dict', options=netapp_utils.na_ontap_host_argument_spec_peer()),
            dest_hostname=dict(required=False, type='str'),
            dest_username=dict(required=False, type='str'),
            dest_password=dict(required=False, type='str', no_log=True)
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            mutually_exclusive=[
                ['peer_options', 'dest_hostname'],
                ['peer_options', 'dest_username'],
                ['peer_options', 'dest_password']
            ],
            supports_check_mode=True
        )

        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)
        if self.parameters.get('dest_hostname') is None and self.parameters.get('peer_options') is None:
            self.parameters['dest_hostname'] = self.parameters.get('hostname')
        if self.parameters.get('dest_hostname') is not None:
            # if dest_hostname is present, peer_options is absent
            self.parameters['peer_options'] = dict(
                hostname=self.parameters.get('dest_hostname'),
                username=self.parameters.get('dest_username'),
                password=self.parameters.get('dest_password'),
            )
        else:
            self.parameters['dest_hostname'] = self.parameters['peer_options']['hostname']
        netapp_utils.setup_host_options_from_module_params(
            self.parameters['peer_options'], self.module,
            netapp_utils.na_ontap_host_argument_spec_peer().keys())
        # Rest API objects
        self.use_rest = False
        self.rest_api = OntapRestAPI(self.module)
        self.src_use_rest = self.rest_api.is_rest()
        self.dst_rest_api = OntapRestAPI(self.module, host_options=self.parameters['peer_options'])
        self.dst_use_rest = self.dst_rest_api.is_rest()
        self.use_rest = bool(self.src_use_rest and self.dst_use_rest)
        if self.use_rest:
            self.peer_relation_uuid = None
        else:
            if not netapp_utils.has_netapp_lib():
                self.module.fail_json(msg=netapp_utils.netapp_lib_is_required())
            self.server = netapp_utils.setup_na_ontap_zapi(module=self.module)
            self.dest_server = netapp_utils.setup_na_ontap_zapi(module=self.module, host_options=self.parameters['peer_options'])

    def vserver_peer_get_iter(self, target):
        """
        Compose NaElement object to query current vserver using remote-vserver-name and vserver parameters.
        :return: NaElement object for vserver-get-iter with query
        """
        vserver_peer_get = netapp_utils.zapi.NaElement('vserver-peer-get-iter')
        query = netapp_utils.zapi.NaElement('query')
        vserver_peer_info = netapp_utils.zapi.NaElement('vserver-peer-info')
        vserver, remote_vserver = self.get_local_and_peer_vserver(target)
        vserver_peer_info.add_new_child('remote-vserver-name', remote_vserver)
        vserver_peer_info.add_new_child('vserver', vserver)
        query.add_child_elem(vserver_peer_info)
        vserver_peer_get.add_child_elem(query)
        return vserver_peer_get

    def get_local_and_peer_vserver(self, target):
        if target == 'source':
            return self.parameters['vserver'], self.parameters['peer_vserver']
        # else for target peer.
        return self.parameters['peer_vserver'], self.parameters['vserver']

    def vserver_peer_get(self, target='source'):
        """
        Get current vserver peer info
        :return: Dictionary of current vserver peer details if query successful, else return None
        """
        if self.use_rest:
            return self.vserver_peer_get_rest(target)

        vserver_peer_get_iter = self.vserver_peer_get_iter(target)
        vserver_info = {}
        try:
            if target == 'source':
                result = self.server.invoke_successfully(vserver_peer_get_iter, enable_tunneling=True)
            elif target == 'peer':
                result = self.dest_server.invoke_successfully(vserver_peer_get_iter, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error fetching vserver peer %s: %s'
                                      % (self.parameters['vserver'], to_native(error)),
                                  exception=traceback.format_exc())
        # return vserver peer details
        if result.get_child_by_name('num-records') and \
                int(result.get_child_content('num-records')) > 0:
            vserver_peer_info = result.get_child_by_name('attributes-list').get_child_by_name('vserver-peer-info')
            vserver_info['peer_vserver'] = vserver_peer_info.get_child_content('remote-vserver-name')
            vserver_info['vserver'] = vserver_peer_info.get_child_content('vserver')
            vserver_info['local_peer_vserver'] = vserver_peer_info.get_child_content('peer-vserver')       # required for delete and accept
            vserver_info['peer_state'] = vserver_peer_info.get_child_content('peer-state')
            return vserver_info
        return None

    def vserver_peer_delete(self, current):
        """
        Delete a vserver peer
        """
        if self.use_rest:
            return self.vserver_peer_delete_rest(current)

        vserver_peer_delete = netapp_utils.zapi.NaElement.create_node_with_children(
            'vserver-peer-delete', **{'peer-vserver': current['local_peer_vserver'],
                                      'vserver': self.parameters['vserver']})
        try:
            self.server.invoke_successfully(vserver_peer_delete,
                                            enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error deleting vserver peer %s: %s'
                                      % (self.parameters['vserver'], to_native(error)),
                                  exception=traceback.format_exc())

    def get_peer_cluster_name(self):
        """
        Get local cluster name
        :return: cluster name
        """
        if self.use_rest:
            return self.get_peer_cluster_name_rest()

        cluster_info = netapp_utils.zapi.NaElement('cluster-identity-get')
        # if remote peer exist , get remote cluster name else local cluster name
        server = self.dest_server if self.is_remote_peer() else self.server
        try:
            result = server.invoke_successfully(cluster_info, enable_tunneling=True)
            return result.get_child_by_name('attributes').get_child_by_name(
                'cluster-identity-info').get_child_content('cluster-name')
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error fetching peer cluster name for peer vserver %s: %s'
                                      % (self.parameters['peer_vserver'], to_native(error)),
                                  exception=traceback.format_exc())

    def vserver_peer_create(self):
        """
        Create a vserver peer
        """
        if self.parameters.get('applications') is None:
            self.module.fail_json(msg='applications parameter is missing')
        if self.parameters.get('peer_cluster') is None:
            self.parameters['peer_cluster'] = self.get_peer_cluster_name()
        if self.use_rest:
            return self.vserver_peer_create_rest()

        vserver_peer_create = netapp_utils.zapi.NaElement.create_node_with_children(
            'vserver-peer-create', **{'peer-vserver': self.parameters['peer_vserver'],
                                      'vserver': self.parameters['vserver'],
                                      'peer-cluster': self.parameters['peer_cluster']})
        if 'local_name_for_peer' in self.parameters:
            vserver_peer_create.add_new_child('local-name', self.parameters['local_name_for_peer'])
        applications = netapp_utils.zapi.NaElement('applications')
        for application in self.parameters['applications']:
            applications.add_new_child('vserver-peer-application', application)
        vserver_peer_create.add_child_elem(applications)
        try:
            self.server.invoke_successfully(vserver_peer_create, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error creating vserver peer %s: %s'
                                  % (self.parameters['vserver'], to_native(error)),
                                  exception=traceback.format_exc())

    def is_remote_peer(self):
        return (
            self.parameters.get('dest_hostname') is not None
            and self.parameters['dest_hostname'] != self.parameters['hostname']
        )

    def vserver_peer_accept(self):
        """
        Accept a vserver peer at destination
        """
        # peer-vserver -> remote (source vserver is provided)
        # vserver -> local (destination vserver is provided)
        if self.use_rest:
            return self.vserver_peer_accept_rest('peer')
        vserver_peer_info = self.vserver_peer_get('peer')
        if vserver_peer_info is None:
            self.module.fail_json(msg='Error retrieving vserver peer information while accepting')
        vserver_peer_accept = netapp_utils.zapi.NaElement.create_node_with_children(
            'vserver-peer-accept', **{'peer-vserver': vserver_peer_info['local_peer_vserver'], 'vserver': self.parameters['peer_vserver']})
        if 'local_name_for_source' in self.parameters:
            vserver_peer_accept.add_new_child('local-name', self.parameters['local_name_for_source'])
        try:
            self.dest_server.invoke_successfully(vserver_peer_accept, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error accepting vserver peer %s: %s'
                                  % (self.parameters['peer_vserver'], to_native(error)),
                                  exception=traceback.format_exc())

    def check_and_report_rest_error(self, error, action, where):
        if error:
            if "job reported error:" in error and "entry doesn't exist" in error:
                # ignore RBAC issue with FSx - BURT1467620 (fixed in 9.11.0) - GitHub #45
                self.module.warn('Ignoring job status, assuming success - Issue #45.')
                return
            self.module.fail_json(msg='Error %s vserver peer relationship on %s: %s' % (action, where, error))

    def vserver_peer_accept_rest(self, target):
        vserver_peer_info = self.vserver_peer_get_rest('peer')
        if not vserver_peer_info:
            self.module.fail_json(msg='Error reading vserver peer information on peer %s' % self.parameters['peer_vserver'])
        api = 'svm/peers'
        body = {"state": "peered"}
        if 'local_name_for_source' in self.parameters:
            body['name'] = self.parameters['local_name_for_source']
        dummy, error = rest_generic.patch_async(self.dst_rest_api, api, vserver_peer_info['local_peer_vserver_uuid'], body)
        self.check_and_report_rest_error(error, 'accepting', self.parameters['peer_vserver'])

    def vserver_peer_get_rest(self, target):
        """
        Get current vserver peer info
        :return: Dictionary of current vserver peer details if query successful, else return None
        """
        api = 'svm/peers'
        vserver_info = {}
        vserver, remote_vserver = self.get_local_and_peer_vserver(target)
        restapi = self.rest_api if target == 'source' else self.dst_rest_api
        options = {'svm.name': vserver, 'peer.svm.name': remote_vserver, 'fields': 'name,svm.name,peer.svm.name,state,uuid'}
        # peer cluster may have multiple peer relationships
        # filter by the created relationship uuid
        if target == 'peer' and self.peer_relation_uuid is not None:
            options['uuid'] = self.peer_relation_uuid
        record, error = rest_generic.get_one_record(restapi, api, options)
        if error:
            self.module.fail_json(msg='Error fetching vserver peer %s: %s' % (self.parameters['vserver'], error))
        if record is not None:
            vserver_info['vserver'] = self.na_helper.safe_get(record, ['svm', 'name'])
            vserver_info['peer_vserver'] = self.na_helper.safe_get(record, ['peer', 'svm', 'name'])
            vserver_info['peer_state'] = record.get('state')
            # required local_peer_vserver_uuid to delete the peer relationship
            vserver_info['local_peer_vserver_uuid'] = record.get('uuid')
            vserver_info['local_peer_vserver'] = record['name']
            return vserver_info
        return None

    def vserver_peer_delete_rest(self, current):
        """
        Delete a vserver peer using rest.
        """
        dummy, error = rest_generic.delete_async(self.rest_api, 'svm/peers', current['local_peer_vserver_uuid'])
        self.check_and_report_rest_error(error, 'deleting', self.parameters['vserver'])

    def get_peer_cluster_name_rest(self):
        """
        Get local cluster name
        :return: cluster name
        """
        api = 'cluster'
        options = {'fields': 'name'}
        # if remote peer exist , get remote cluster name else local cluster name
        restapi = self.dst_rest_api if self.is_remote_peer() else self.rest_api
        record, error = rest_generic.get_one_record(restapi, api, options)
        if error:
            self.module.fail_json(msg='Error fetching peer cluster name for peer vserver %s: %s'
                                      % (self.parameters['peer_vserver'], error))
        if record is not None:
            return record.get('name')
        return None

    def vserver_peer_create_rest(self):
        """
        Create a vserver peer using rest
        """
        api = 'svm/peers'
        query = {'return_records': 'true'}
        body = {
            'svm.name': self.parameters['vserver'],
            'peer.cluster.name': self.parameters['peer_cluster'],
            'peer.svm.name': self.parameters['peer_vserver'],
            'applications': self.parameters['applications']
        }
        if 'local_name_for_peer' in self.parameters:
            body['name'] = self.parameters['local_name_for_peer']
        record, error = rest_generic.post_async(self.rest_api, api, body, query)
        self.check_and_report_rest_error(error, 'creating', self.parameters['vserver'])
        if record.get('records') is not None:
            self.peer_relation_uuid = record['records'][0].get('uuid')

    def apply(self):
        """
        Apply action to create/delete or accept vserver peer
        """
        current = self.vserver_peer_get()
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        if self.na_helper.changed and not self.module.check_mode:
            if cd_action == 'create':
                self.vserver_peer_create()
                # accept only if the peer relationship is on a remote cluster
                if self.is_remote_peer():
                    self.vserver_peer_accept()
            elif cd_action == 'delete':
                self.vserver_peer_delete(current)
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action)
        self.module.exit_json(**result)


def main():
    """Execute action"""
    module_obj = NetAppONTAPVserverPeer()
    module_obj.apply()


if __name__ == '__main__':
    main()
