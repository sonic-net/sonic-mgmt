#!/usr/bin/python

# (c) 2018-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
  - Create/Delete cluster peer relations on ONTAP
  - Modify remote intercluster addresses in cluster peer relation on ONTAP
extends_documentation_fragment:
  - netapp.ontap.netapp.na_ontap
  - netapp.ontap.netapp.na_ontap_peer
module: na_ontap_cluster_peer
options:
  state:
    choices: ['present', 'absent']
    type: str
    description:
      - Whether the specified cluster peer should exist or not.
    default: present
  source_intercluster_lifs:
    description:
      - List of intercluster addresses of the source cluster.
      - Used as peer-addresses in destination cluster.
      - All these intercluster lifs should belong to the source cluster.
    version_added: 2.8.0
    type: list
    elements: str
    aliases:
    - source_intercluster_lif
  dest_intercluster_lifs:
    description:
      - List of intercluster addresses of the destination cluster.
      - Used as peer-addresses in source cluster.
      - All these intercluster lifs should belong to the destination cluster.
    version_added: 2.8.0
    type: list
    elements: str
    aliases:
    - dest_intercluster_lif
  passphrase:
    description:
      - The arbitrary passphrase that matches the one given to the peer cluster.
    type: str
  source_cluster_name:
    description:
      - The name of the source cluster name in the peer relation to be modified or deleted.
      - Required for deleting peer relation and for modifying source_intercluster_lifs.
    type: str
  dest_cluster_name:
    description:
      - The name of the destination cluster name in the peer relation to be modified or deleted.
      - Required for deleting peer relation and for modifying dest_intercluster_lifs.
    type: str
  dest_hostname:
    description:
      - DEPRECATED - please use C(peer_options).
      - Destination cluster IP or hostname which needs to be peered.
      - Required to complete the peering process at destination cluster.
    type: str
  dest_username:
    description:
      - DEPRECATED - please use C(peer_options).
      - Destination username.
      - Optional if this is same as source username or if a certificate is used.
    type: str
  dest_password:
    description:
      - DEPRECATED - please use C(peer_options).
      - Destination password.
      - Optional if this is same as source password or if a certificate is used..
    type: str
  ipspace:
    description:
    - IPspace of the local intercluster LIFs.
    - Assumes Default IPspace if not provided.
    type: str
    version_added: '20.11.0'
  encryption_protocol_proposed:
    description:
     - Encryption protocol to be used for inter-cluster communication.
     - Only available on ONTAP 9.5 or later.
    choices: ['tls_psk', 'none']
    type: str
    version_added: '20.5.0'
  local_name_for_peer:
    description:
      - Specifies local name of the peer Cluster in the relationship.
      - By default the system will generate the same name as cluster name.
    type: str
    version_added: '23.1.0'
  local_name_for_source:
    description:
      - Specifies local name of the source Cluster in the relationship.
      - By default the system will generate the same name as cluster name.
    type: str
    version_added: '23.1.0'
short_description: NetApp ONTAP Manage Cluster peering
version_added: 2.7.0

notes:
  - Modify remote intercluster addresses operation is supported only with REST.
  - The options local_name_for_peer and local_name_for_source are supported only with REST.
'''

EXAMPLES = """
- name: Create cluster peer
  netapp.ontap.na_ontap_cluster_peer:
    state: present
    source_intercluster_lifs: 1.2.3.4,1.2.3.5
    dest_intercluster_lifs: 1.2.3.6,1.2.3.7
    passphrase: XXXX
    local_name_for_peer: 'dest_local_name'
    local_name_for_source: 'sorce_local_name'
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    peer_options:
      hostname: "{{ dest_netapp_hostname }}"
    encryption_protocol_proposed: tls_psk

- name: Delete cluster peer
  netapp.ontap.na_ontap_cluster_peer:
    state: absent
    source_cluster_name: test-source-cluster
    dest_cluster_name: test-dest-cluster
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    peer_options:
      hostname: "{{ dest_netapp_hostname }}"

- name: Create cluster peer - different credentials
  netapp.ontap.na_ontap_cluster_peer:
    state: present
    source_intercluster_lifs: 1.2.3.4,1.2.3.5
    dest_intercluster_lifs: 1.2.3.6,1.2.3.7
    passphrase: XXXX
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    peer_options:
      hostname: "{{ dest_netapp_hostname }}"
      cert_filepath: "{{ cert_filepath }}"
      key_filepath: "{{ key_filepath }}"
    encryption_protocol_proposed: tls_psk

- name: Modify cluster peer - destination intercluster addresses
  netapp.ontap.na_ontap_cluster_peer:
    state: present
    source_intercluster_lifs: 1.2.3.4,1.2.3.5
    dest_intercluster_lifs: 1.2.3.8
    dest_cluster_name: test-dest-cluster
    local_name_for_peer: 'dest_name'
    local_name_for_source: 'source_name'
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    peer_options:
      hostname: "{{ dest_netapp_hostname }}"
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


class NetAppONTAPClusterPeer:
    """
    Class with cluster peer methods
    """

    def __init__(self):

        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            source_intercluster_lifs=dict(required=False, type='list', elements='str', aliases=['source_intercluster_lif']),
            dest_intercluster_lifs=dict(required=False, type='list', elements='str', aliases=['dest_intercluster_lif']),
            passphrase=dict(required=False, type='str', no_log=True),
            peer_options=dict(type='dict', options=netapp_utils.na_ontap_host_argument_spec_peer()),
            dest_hostname=dict(required=False, type='str'),
            dest_username=dict(required=False, type='str'),
            dest_password=dict(required=False, type='str', no_log=True),
            source_cluster_name=dict(required=False, type='str'),
            dest_cluster_name=dict(required=False, type='str'),
            ipspace=dict(required=False, type='str'),
            encryption_protocol_proposed=dict(required=False, type='str', choices=['tls_psk', 'none']),
            local_name_for_peer=dict(required=False, type='str'),
            local_name_for_source=dict(required=False, type='str'),
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            mutually_exclusive=[
                ['peer_options', 'dest_hostname'],
                ['peer_options', 'dest_username'],
                ['peer_options', 'dest_password']
            ],
            required_one_of=[['peer_options', 'dest_hostname']],
            required_if=[
                ('state', 'absent', ['source_cluster_name', 'dest_cluster_name']),
                ('state', 'present', ['source_intercluster_lifs', 'dest_intercluster_lifs'])
            ],
            supports_check_mode=True
        )
        self.generated_passphrase = None
        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)
        # set peer server connection
        if self.parameters.get('dest_hostname') is not None:
            # if dest_hostname is present, peer_options is absent
            self.parameters['peer_options'] = dict(
                hostname=self.parameters.get('dest_hostname'),
                username=self.parameters.get('dest_username'),
                password=self.parameters.get('dest_password'),
            )
        netapp_utils.setup_host_options_from_module_params(
            self.parameters['peer_options'], self.module,
            netapp_utils.na_ontap_host_argument_spec_peer().keys())
        self.use_rest = False
        self.rest_api = OntapRestAPI(self.module)
        self.src_use_rest = self.rest_api.is_rest()
        self.dst_rest_api = OntapRestAPI(self.module, host_options=self.parameters['peer_options'])
        self.dst_use_rest = self.dst_rest_api.is_rest()
        self.use_rest = bool(self.src_use_rest and self.dst_use_rest)
        if not self.use_rest:
            if not netapp_utils.has_netapp_lib():
                self.module.fail_json(msg="the python NetApp-Lib module is required")
            self.server = netapp_utils.setup_na_ontap_zapi(module=self.module)
            self.dest_server = netapp_utils.setup_na_ontap_zapi(module=self.module, host_options=self.parameters['peer_options'])

    def cluster_peer_get_iter(self, cluster):
        """
        Compose NaElement object to query current source cluster using peer-cluster-name and peer-addresses parameters
        :param cluster: type of cluster (source or destination)
        :return: NaElement object for cluster-get-iter with query
        """
        cluster_peer_get = netapp_utils.zapi.NaElement('cluster-peer-get-iter')
        query = netapp_utils.zapi.NaElement('query')
        cluster_peer_info = netapp_utils.zapi.NaElement('cluster-peer-info')
        peer_lifs, peer_cluster = self.get_peer_lifs_cluster_keys(cluster)
        if self.parameters.get(peer_lifs):
            peer_addresses = netapp_utils.zapi.NaElement('peer-addresses')
            for peer in self.parameters.get(peer_lifs):
                peer_addresses.add_new_child('remote-inet-address', peer)
            cluster_peer_info.add_child_elem(peer_addresses)
        if self.parameters.get(peer_cluster):
            cluster_peer_info.add_new_child('cluster-name', self.parameters[peer_cluster])
        query.add_child_elem(cluster_peer_info)
        cluster_peer_get.add_child_elem(query)
        return cluster_peer_get

    def cluster_peer_get(self, cluster):
        """
        Get current cluster peer info
        :param cluster: type of cluster (source or destination)
        :return: Dictionary of current cluster peer details if query successful, else return None
        """
        if self.use_rest:
            return self.cluster_peer_get_rest(cluster)
        cluster_peer_get_iter = self.cluster_peer_get_iter(cluster)
        result, cluster_info = None, dict()
        if cluster == 'source':
            server = self.server
        else:
            server = self.dest_server
        try:
            result = server.invoke_successfully(cluster_peer_get_iter, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error fetching cluster peer %s: %s'
                                  % (cluster, to_native(error)),
                                  exception=traceback.format_exc())
        # return cluster peer details
        if result.get_child_by_name('num-records') and \
                int(result.get_child_content('num-records')) >= 1:
            cluster_peer_info = result.get_child_by_name('attributes-list').get_child_by_name('cluster-peer-info')
            cluster_info['cluster_name'] = cluster_peer_info.get_child_content('cluster-name')
            peers = cluster_peer_info.get_child_by_name('peer-addresses')
            cluster_info['peer-addresses'] = [peer.get_content() for peer in peers.get_children()]
            return cluster_info
        return None

    def get_peer_lifs_cluster_keys(self, cluster):
        if cluster == 'source':
            return 'dest_intercluster_lifs', 'dest_cluster_name'
        return 'source_intercluster_lifs', 'source_cluster_name'

    def cluster_peer_get_rest(self, cluster):
        api = 'cluster/peers'
        fields = 'remote,name'
        restapi = self.rest_api if cluster == 'source' else self.dst_rest_api
        records, error = rest_generic.get_0_or_more_records(restapi, api, None, fields)
        if error:
            self.module.fail_json(msg=error)
        cluster_info = {}
        if records is not None:
            peer_lifs, peer_cluster = self.get_peer_lifs_cluster_keys(cluster)
            for record in records:
                if 'remote' in record:
                    peer_cluster_exist, peer_addresses_exist = False, False
                    # check peer lif or peer cluster present in each peer cluster data in current.
                    # if peer-lifs not present in parameters, use peer_cluster to filter desired cluster peer in current.
                    if self.parameters.get(peer_lifs) is not None:
                        peer_addresses_exist = set(self.parameters[peer_lifs]) == set(record['remote']['ip_addresses'])
                    if self.parameters.get(peer_cluster) is not None:
                        peer_cluster_exist = self.parameters[peer_cluster] == record['remote']['name']
                    if peer_addresses_exist or peer_cluster_exist:
                        cluster_info['cluster_name'] = record['remote']['name']
                        cluster_info['peer-addresses'] = record['remote']['ip_addresses']
                        cluster_info['uuid'] = record['uuid']
                        cluster_info['local_name_for_peer'] = record['name']
                        return cluster_info
        return None

    def cluster_peer_delete(self, cluster, uuid=None):
        """
        Delete a cluster peer on source or destination
        For source cluster, peer cluster-name = destination cluster name and vice-versa
        :param cluster: type of cluster (source or destination)
        :return:
        """
        if self.use_rest:
            return self.cluster_peer_delete_rest(cluster, uuid)
        if cluster == 'source':
            server, peer_cluster_name = self.server, self.parameters['dest_cluster_name']
        else:
            server, peer_cluster_name = self.dest_server, self.parameters['source_cluster_name']
        cluster_peer_delete = netapp_utils.zapi.NaElement.create_node_with_children(
            'cluster-peer-delete', **{'cluster-name': peer_cluster_name})
        try:
            server.invoke_successfully(cluster_peer_delete, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error deleting cluster peer %s: %s'
                                      % (peer_cluster_name, to_native(error)),
                                  exception=traceback.format_exc())

    def cluster_peer_delete_rest(self, cluster, uuid):
        server = self.rest_api if cluster == 'source' else self.dst_rest_api
        dummy, error = rest_generic.delete_async(server, 'cluster/peers', uuid)
        if error:
            self.module.fail_json(msg=error)

    def cluster_peer_create(self, cluster):
        """
        Create a cluster peer on source or destination
        For source cluster, peer addresses = destination inter-cluster LIFs and vice-versa
        :param cluster: type of cluster (source or destination)
        :return: None
        """
        if self.use_rest:
            return self.cluster_peer_create_rest(cluster)
        cluster_peer_create = netapp_utils.zapi.NaElement.create_node_with_children('cluster-peer-create')
        if self.parameters.get('passphrase') is not None:
            cluster_peer_create.add_new_child('passphrase', self.parameters['passphrase'])
        peer_addresses = netapp_utils.zapi.NaElement('peer-addresses')
        server, peer_address = self.get_server_and_peer_address(cluster)
        for each in peer_address:
            peer_addresses.add_new_child('remote-inet-address', each)
        cluster_peer_create.add_child_elem(peer_addresses)
        if self.parameters.get('encryption_protocol_proposed') is not None:
            cluster_peer_create.add_new_child('encryption-protocol-proposed', self.parameters['encryption_protocol_proposed'])
        if self.parameters.get('ipspace') is not None:
            cluster_peer_create.add_new_child('ipspace-name', self.parameters['ipspace'])

        try:
            server.invoke_successfully(cluster_peer_create, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error creating cluster peer %s: %s'
                                  % (peer_address, to_native(error)),
                                  exception=traceback.format_exc())

    def get_server_and_peer_address(self, cluster):
        if cluster == 'source':
            server = self.rest_api if self.use_rest else self.server
            return server, self.parameters['dest_intercluster_lifs']
        server = self.dst_rest_api if self.use_rest else self.dest_server
        return server, self.parameters['source_intercluster_lifs']

    def cluster_peer_create_rest(self, cluster):
        api = 'cluster/peers'
        body = {}
        if self.parameters.get('passphrase') is not None:
            body['authentication.passphrase'] = self.parameters['passphrase']
        # generate passphrase in source if passphrase not provided.
        elif cluster == 'source':
            body['authentication.generate_passphrase'] = True
            if 'local_name_for_peer' in self.parameters:
                body['name'] = self.parameters['local_name_for_peer']
        elif cluster == 'destination':
            body['authentication.passphrase'] = self.generated_passphrase
            if 'local_name_for_source' in self.parameters:
                body['name'] = self.parameters['local_name_for_source']
        server, peer_address = self.get_server_and_peer_address(cluster)
        body['remote.ip_addresses'] = peer_address
        if self.parameters.get('encryption_protocol_proposed') is not None:
            body['encryption.proposed'] = self.parameters['encryption_protocol_proposed']
        else:
            # Default value for encryption.proposed is tls_psk.
            # explicitly set to none if encryption_protocol_proposed options not present in parameters.
            body['encryption.proposed'] = 'none'
        if self.parameters.get('ipspace') is not None:
            body['ipspace.name'] = self.parameters['ipspace']
        response, error = rest_generic.post_async(server, api, body)
        if error:
            self.module.fail_json(msg=error)
        if response and cluster == 'source' and 'passphrase' not in self.parameters:
            for record in response['records']:
                self.generated_passphrase = record['authentication']['passphrase']

    def cluster_peer_modify_rest(self, cluster, uuid, modified_peer_addresses=None, local_name=None, current_name=None):
        api = 'cluster/peers'
        body = {}
        if modified_peer_addresses:
            body['remote.ip_addresses'] = modified_peer_addresses
        if local_name and local_name != current_name:
            body['name'] = local_name
        server = self.rest_api if cluster == 'source' else self.dst_rest_api
        dummy, error = rest_generic.patch_async(server, api, uuid, body)
        if error:
            self.module.fail_json(msg=error)

    def apply(self):
        """
        Apply action to cluster peer
        :return: None
        """
        modify = {}
        source = self.cluster_peer_get('source')
        destination = self.cluster_peer_get('destination')
        source_action = self.na_helper.get_cd_action(source, self.parameters)
        destination_action = self.na_helper.get_cd_action(destination, self.parameters)
        self.na_helper.changed = False

        # create only if expected cluster peer relation is not present on both source and destination clusters
        # will error out with appropriate message if peer relationship already exists on either cluster
        if source_action == 'create' and destination_action == 'create':
            if not self.module.check_mode:
                self.cluster_peer_create('source')
                self.cluster_peer_create('destination')
            self.na_helper.changed = True
        # check and modify IP addresses of the logical interfaces used in peer relation
        # on either source or destination cluster
        elif self.use_rest and (source_action is None or destination_action is None):
            source_changed, destination_changed = False, False
            if source_action is None:
                if destination_action == 'create' and self.parameters.get('source_cluster_name') is None:
                    self.module.fail_json(msg='Following option is missing: source_cluster_name')
                if not self.module.check_mode:
                    if source:
                        peer_address_diff = set(source.get('peer-addresses', [])) != set(self.parameters.get('dest_intercluster_lifs', []))
                        local_name_diff = (
                            self.parameters.get('local_name_for_peer') and
                            source.get('local_name_for_peer') != self.parameters.get('local_name_for_peer')
                        )
                        if peer_address_diff or local_name_diff:
                            source_changed = True
                            uuid = source['uuid']
                            modified_peer_addresses = self.parameters['dest_intercluster_lifs'] if peer_address_diff else None
                            current_name = source.get('local_name_for_peer')
                            local_name = self.parameters.get('local_name_for_peer') if local_name_diff else None
                            self.cluster_peer_modify_rest('source', uuid, modified_peer_addresses, local_name, current_name)
                            if peer_address_diff:
                                modify['dest_intercluster_lifs'] = self.parameters['dest_intercluster_lifs']
                            if local_name_diff:
                                modify['local_name_for_peer'] = self.parameters['local_name_for_peer']
            if destination_action is None:
                if source_action == 'create' and self.parameters.get('dest_cluster_name') is None:
                    self.module.fail_json(msg='Following option is missing: dest_cluster_name')
                if not self.module.check_mode:
                    if destination:
                        peer_address_diff = set(destination.get('peer-addresses', [])) != set(self.parameters.get('source_intercluster_lifs', []))
                        local_name_diff = (
                            self.parameters.get('local_name_for_source') and
                            destination.get('local_name_for_peer') != self.parameters.get('local_name_for_source')
                        )
                        if peer_address_diff or local_name_diff:
                            destination_changed = True
                            uuid = destination['uuid']
                            modified_peer_addresses = self.parameters['source_intercluster_lifs'] if peer_address_diff else None
                            local_name = self.parameters.get('local_name_for_source') if local_name_diff else None
                            self.cluster_peer_modify_rest('destination', uuid, modified_peer_addresses, local_name)
                            if peer_address_diff:
                                modify['source_intercluster_lifs'] = self.parameters['source_intercluster_lifs']
                            if local_name_diff:
                                modify['local_name_for_peer'] = self.parameters['local_name_for_source']
            self.na_helper.changed = source_changed | destination_changed
        # delete peer relation in cluster where relation is present
        else:
            if source_action == 'delete':
                if not self.module.check_mode:
                    uuid = source['uuid'] if source and self.use_rest else None
                    self.cluster_peer_delete('source', uuid)
                self.na_helper.changed = True
            if destination_action == 'delete':
                if not self.module.check_mode:
                    uuid = destination['uuid'] if destination and self.use_rest else None
                    self.cluster_peer_delete('destination', uuid)
                self.na_helper.changed = True

        result = netapp_utils.generate_result(self.na_helper.changed, modify=modify, extra_responses={'source_action': source_action,
                                                                                                      'destination_action': destination_action})
        self.module.exit_json(**result)


def main():
    """
    Execute action
    :return: None
    """
    cluster_peer_obj = NetAppONTAPClusterPeer()
    cluster_peer_obj.apply()


if __name__ == '__main__':
    main()
